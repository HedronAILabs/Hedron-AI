//! Hedron Core Library - Enterprise Multi-Agent Framework
//!
//! Implements distributed agent management, Byzantine fault tolerance,
//! and zero-trust security protocols.

#![forbid(unsafe_code)]
#![warn(missing_docs, clippy::all, clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]

use std::{
    collections::{BTreeMap, HashMap},
    sync::Arc,
    time::{Duration, SystemTime},
};

use async_trait::async_trait;
use bytes::Bytes;
use ed25519_dalek::{Signer, Verifier};
use futures::{
    stream::{BoxStream, SplitStream},
    StreamExt,
};
use prost::Message;
use ring::{
    aead::{Aad, BoundKey, Nonce, NonceSequence, OpeningKey, SealingKey, AES_256_GCM},
    rand::SystemRandom,
};
use serde::{Deserialize, Serialize};
use tokio::{
    net::TcpStream,
    sync::{Mutex, RwLock},
};
use tokio_rustls::client::TlsStream;
use tokio_util::codec::{Framed, LengthDelimitedCodec};
use tonic::transport::Channel;
use uuid::Uuid;

pub mod crypto;
pub mod error;
pub mod metrics;
pub mod storage;

use crate::{
    crypto::{KeyRotationManager, QuantumResistantSigner},
    error::HedronError,
    metrics::AgentMetricsRecorder,
    storage::{DistributedLedger, EncryptedKvStore},
};

// =============================================================================
// Core Protocol Constants
// =============================================================================

/// Byzantine Fault Tolerance configuration
pub const PBFT_VIEW_CHANGE_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_CONCURRENT_OPS: usize = 10_000;
const REPLICATION_FACTOR: usize = 5;

// =============================================================================
// Core Data Structures
// =============================================================================

#[derive(Debug, Clone, Serialize, Deserialize, Message)]
pub struct AgentManifest {
    #[prost(string, tag = "1")]
    pub agent_id: String,
    #[prost(bytes, tag = "2")]
    pub public_key: Vec<u8>,
    #[prost(uint64, tag = "3")]
    pub sequence_number: u64,
    #[prost(message, repeated, tag = "4")]
    pub capabilities: Vec<AgentCapability>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Message)]
pub struct AgentCapability {
    #[prost(string, tag = "1")]
    pub protocol: String,
    #[prost(uint32, tag = "2")]
    pub version_mask: u32,
    #[prost(bytes, tag = "3")]
    pub attestation: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Message)]
pub struct SignedMessage {
    #[prost(bytes, tag = "1")]
    pub payload: Vec<u8>,
    #[prost(bytes, tag = "2")]
    pub signature: Vec<u8>,
    #[prost(fixed64, tag = "3")]
    pub timestamp: u64,
}

// =============================================================================
// Enterprise Agent Framework
// =============================================================================

#[async_trait]
pub trait EnterpriseAgent: Send + Sync {
    async fn submit_transaction(
        &self,
        tx: SignedMessage,
    ) -> Result<BoxStream<'static, Result<SignedMessage, HedronError>>, HedronError>;
    
    async fn replicate_state(
        &self,
        state_chunk: Bytes,
    ) -> Result<(), HedronError>;
    
    async fn verify_byzantine_proof(
        &self,
        proof: Bytes,
    ) -> Result<bool, HedronError>;
}

#[derive(Clone)]
pub struct SecureAgentBroker {
    ledger: Arc<dyn DistributedLedger>,
    kv_store: Arc<dyn EncryptedKvStore>,
    crypto_suite: Arc<QuantumResistantSigner>,
    metrics: Arc<AgentMetricsRecorder>,
    key_rotator: Arc<KeyRotationManager>,
    active_connections: Arc<RwLock<HashMap<Uuid, TlsStream<TcpStream>>>>,
}

impl SecureAgentBroker {
    pub async fn new(
        config: AgentConfig,
    ) -> Result<Self, HedronError> {
        let crypto_suite = QuantumResistantSigner::initialize(
            config.crypto_config,
            config.quantum_seed,
        )?;
        
        let ledger = DistributedLedger::bootstrap(
            config.ledger_config,
            crypto_suite.clone(),
        ).await?;
        
        let kv_store = EncryptedKvStore::with_auto_rotation(
            config.storage_config,
            crypto_suite.clone(),
        )?;

        Ok(Self {
            ledger: Arc::new(ledger),
            kv_store: Arc::new(kv_store),
            crypto_suite: Arc::new(crypto_suite),
            metrics: Arc::new(AgentMetricsRecorder::new()),
            key_rotator: Arc::new(KeyRotationManager::with_schedule(
                config.rotation_schedule,
            )?),
            active_connections: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    pub async fn establish_secure_channel(
        &self,
        endpoint: &str,
    ) -> Result<Uuid, HedronError> {
        let tls_config = self.crypto_suite.build_tls_config()?;
        let tcp_stream = TcpStream::connect(endpoint).await?;
        let tls_stream = tls_config.connect(endpoint, tcp_stream).await?;
        let conn_id = Uuid::new_v4();
        
        let mut conns = self.active_connections.write().await;
        conns.insert(conn_id, tls_stream);
        
        Ok(conn_id)
    }

    pub async fn submit_pbft_preprepare(
        &self,
        request: PbftPrePrepare,
    ) -> Result<PbftResponse, HedronError> {
        let mut guard = self.metrics.begin_operation("pbft_preprepare").await;
        let sequence = self.ledger.next_sequence().await?;
        
        let encoded = request.encode_to_vec();
        let signature = self.crypto_suite.sign(&encoded)?;
        
        self.ledger
            .append(SignedMessage {
                payload: encoded,
                signature,
                timestamp: SystemTime::now()
                    .duration_since(SystemTime::UNIX_EPOCH)?
                    .as_secs(),
            })
            .await?;
        
        guard.record_success(sequence).await;
        Ok(PbftResponse::new_accepted(sequence))
    }

    async fn handle_view_change(
        &self,
        view_change: PbftViewChange,
    ) -> Result<(), HedronError> {
        let mut state_lock = self.ledger.state_lock().await?;
        
        if view_change.new_view > state_lock.current_view() {
            state_lock.advance_view(
                view_change.new_view,
                view_change.checkpoint_proof,
            )?;
            
            self.key_rotator.rotate_group_keys(
                view_change.new_view as usize,
            ).await?;
        }
        
        Ok(())
    }
}

#[async_trait]
impl EnterpriseAgent for SecureAgentBroker {
    async fn submit_transaction(
        &self,
        tx: SignedMessage,
    ) -> Result<BoxStream<'static, Result<SignedMessage, HedronError>>, HedronError> {
        self.crypto_suite.verify(&tx.payload, &tx.signature)?;
        
        let sequence = self.ledger.append(tx.clone()).await?;
        let stream = self.ledger.subscribe_from(sequence).await?;
        
        Ok(stream.boxed())
    }

    async fn replicate_state(
        &self,
        state_chunk: Bytes,
    ) -> Result<(), HedronError> {
        let decrypted = self.crypto_suite.decrypt_bulk(state_chunk)?;
        self.ledger.replicate(decrypted).await
    }

    async fn verify_byzantine_proof(
        &self,
        proof: Bytes,
    ) -> Result<bool, HedronError> {
        let merkle_proof: storage::MerkleProof = bincode::deserialize(&proof)?;
        self.ledger.verify_inclusion(merkle_proof).await
    }
}

// =============================================================================
// Byzantine Fault Tolerance Protocol
// =============================================================================

#[derive(Debug, Clone, Serialize, Deserialize, Message)]
pub struct PbftPrePrepare {
    #[prost(uint64, tag = "1")]
    pub view: u64,
    #[prost(uint64, tag = "2")]
    pub sequence: u64,
    #[prost(bytes, tag = "3")]
    pub request_digest: Vec<u8>,
    #[prost(message, optional, tag = "4")]
    pub client_sig: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Message)]
pub struct PbftPrepare {
    #[prost(uint64, tag = "1")]
    pub view: u64,
    #[prost(uint64, tag = "2")]
    pub sequence: u64,
    #[prost(bytes, tag = "3")]
    pub replica_sig: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Message)]
pub struct PbftCommit {
    #[prost(uint64, tag = "1")]
    pub view: u64,
    #[prost(uint64, tag = "2")]
    pub sequence: u64,
    #[prost(bytes, tag = "3")]
    pub replica_sig: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Message)]
pub struct PbftViewChange {
    #[prost(uint64, tag = "1")]
    pub new_view: u64,
    #[prost(bytes, tag = "2")]
    pub checkpoint_proof: Vec<u8>,
    #[prost(message, repeated, tag = "3")]
    pub prepared_proofs: Vec<PbftPrepare>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Message)]
pub struct PbftResponse {
    #[prost(uint64, tag = "1")]
    pub sequence: u64,
    #[prost(bytes, tag = "2")]
    pub result_hash: Vec<u8>,
    #[prost(enumeration = "PbftStatus", tag = "3")]
    pub status: i32,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum PbftStatus {
    Pending = 0,
    Committed = 1,
    ViewChanged = 2,
    FaultDetected = 3,
}

// =============================================================================
// Cryptographic Primitives
// =============================================================================

pub struct AeadNonceSequence {
    current: Nonce,
}

impl NonceSequence for AeadNonceSequence {
    fn advance(&mut self) -> Result<Nonce, ring::error::Unspecified> {
        let mut next = self.current.as_ref().to_vec();
        for byte in next.iter_mut().rev() {
            if let Some(b) = byte.checked_add(1) {
                *byte = b;
                break;
            }
            *byte = 0;
        }
        Nonce::try_assume_unique_for_key(next.as_slice())
    }
}

// =============================================================================
// Enterprise Configuration Structures
// =============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentConfig {
    pub ledger_config: storage::LedgerConfig,
    pub storage_config: storage::StorageConfig,
    pub crypto_config: crypto::CryptoConfig,
    pub rotation_schedule: crypto::RotationSchedule,
    pub quantum_seed: [u8; 32],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkPolicy {
    pub max_message_size: usize,
    pub session_timeout: Duration,
    pub replication_factor: usize,
    pub fault_threshold: f64,
}

// =============================================================================
// Metrics & Monitoring
// =============================================================================

#[derive(Debug)]
pub struct AgentTelemetry {
    pub ops_committed: u64,
    pub view_changes: u64,
    pub avg_commit_latency: f64,
    pub crypto_ops: BTreeMap<String, u64>,
    pub network_throughput: (u64, u64), // (in_bytes, out_bytes)
}

// =============================================================================
// Enterprise Initialization
// =============================================================================

pub async fn initialize_enterprise_cluster(
    config: ClusterConfig,
) -> Result<Arc<SecureAgentBroker>, HedronError> {
    let agent_broker = SecureAgentBroker::new(config.agent_config).await?;
    
    if config.bootstrap_cluster {
        let genesis_block = create_genesis_block(&config)?;
        agent_broker.ledger.append(genesis_block).await?;
    }
    
    Ok(Arc::new(agent_broker))
}

fn create_genesis_block(
    config: &ClusterConfig,
) -> Result<SignedMessage, HedronError> {
    let manifest = AgentManifest {
        agent_id: "genesis".into(),
        public_key: config.agent_config.crypto_config.initial_public_key.clone(),
        sequence_number: 0,
        capabilities: vec![AgentCapability {
            protocol: "PBFT/v4".into(),
            version_mask: 0xFFFF_FFFF,
            attestation: vec![],
        }],
    };
    
    let encoded = manifest.encode_to_vec();
    let signature = QuantumResistantSigner::bootstrap_sign(&encoded)?;
    
    Ok(SignedMessage {
        payload: encoded,
        signature,
        timestamp: SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)?
            .as_secs(),
    })
}

// =============================================================================
// Integration Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::InMemoryLedger;
    
    #[tokio::test]
    async fn test_pbft_consensus_happy_path() {
        let config = test_config();
        let broker = SecureAgentBroker::new(config).await.unwrap();
        
        let preprepare = PbftPrePrepare {
            view: 0,
            sequence: 1,
            request_digest: vec![0u8; 32],
            client_sig: None,
        };
        
        let response = broker.submit_pbft_preprepare(preprepare).await.unwrap();
        assert_eq!(response.status, PbftStatus::Committed as i32);
    }
    
    fn test_config() -> AgentConfig {
        AgentConfig {
            ledger_config: storage::LedgerConfig::InMemory,
            storage_config: storage::StorageConfig::Ephemeral,
            crypto_config: crypto::CryptoConfig::Development,
            rotation_schedule: crypto::RotationSchedule::Never,
            quantum_seed: [0u8; 32],
        }
    }
}
