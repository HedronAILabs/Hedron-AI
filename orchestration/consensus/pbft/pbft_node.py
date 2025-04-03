import asyncio
import hashlib
import json
from dataclasses import dataclass
from datetime import datetime
from typing import Dict, List, Optional, Tuple, Set, Callable, Awaitable
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.exceptions import InvalidSignature
import leveldb
from prometheus_client import Counter, Gauge, Histogram

# =================================================================
# Cryptography Constants
# =================================================================
ED25519_PRIVATE_KEY = ed25519.Ed25519PrivateKey.generate()
ED25519_PUBLIC_KEY = ED25519_PRIVATE_KEY.public_key()
SIGNATURE_DOMAIN = b"hedron-pbft-v1"

# =================================================================
# Prometheus Metrics
# =================================================================
CONSENSUS_LATENCY = Histogram(
    'pbft_consensus_latency_seconds',
    'End-to-end consensus latency',
    ['request_type']
)

VIEW_CHANGES = Counter(
    'pbft_view_change_events_total',
    'Total number of view change events'
)

ACTIVE_VIEW = Gauge(
    'pbft_active_view_number',
    'Currently active view number'
)

# =================================================================
# Core Data Structures
# =================================================================

@dataclass(frozen=True)
class PBFTConfig:
    node_count: int
    fault_tolerance: int
    checkpoint_interval: int = 100
    request_timeout: int = 10  # seconds
    view_change_timeout: int = 30  # seconds
    max_log_size: int = 1_000_000
    db_path: str = "/var/hedron/pbft-state"

class PBFTMessageType:
    REQUEST = 0
    PRE_PREPARE = 1
    PREPARE = 2
    COMMIT = 3
    VIEW_CHANGE = 4
    NEW_VIEW = 5

@dataclass
class PBFTMessage:
    type: int
    view: int
    sequence: int
    digest: str
    sender: int
    signature: bytes
    payload: Optional[bytes] = None

    def sign(self, private_key: ed25519.Ed25519PrivateKey) -> None:
        signing_data = self._serialize_for_signing()
        self.signature = private_key.sign(signing_data, domain=SIGNATURE_DOMAIN)

    def verify(self, public_key: ed25519.Ed25519PublicKey) -> bool:
        try:
            public_key.verify(self.signature, self._serialize_for_signing(), domain=SIGNATURE_DOMAIN)
            return True
        except InvalidSignature:
            return False

    def _serialize_for_signing(self) -> bytes:
        return json.dumps({
            'type': self.type,
            'view': self.view,
            'sequence': self.sequence,
            'digest': self.digest,
            'sender': self.sender
        }).encode()

# =================================================================
# State Management
# =================================================================

class PBFTState:
    def __init__(self, node_id: int, config: PBFTConfig):
        self.node_id = node_id
        self.config = config
        self.view = 0
        self.sequence = 0
        self.log = leveldb.LevelDB(config.db_path)
        self.checkpoints = {}
        self.prepared = set()
        self.committed = set()
        self.active_requests: Dict[int, asyncio.Task] = {}
        self.key_store: Dict[int, ed25519.Ed25519PublicKey] = {}
        self._register_initial_keys()

    def _register_initial_keys(self) -> None:
        # In production, replace with HSM integration
        for nid in range(self.config.node_count):
            self.key_store[nid] = ED25519_PUBLIC_KEY

    def last_checkpoint(self) -> int:
        return max(self.checkpoints.keys(), default=0)

    def validate_sequence(self, sequence: int) -> bool:
        last_seq = self.last_checkpoint() + self.config.checkpoint_interval
        return sequence > self.last_checkpoint() and sequence <= last_seq

# =================================================================
# Core PBFT Node Implementation
# =================================================================

class PBFTConsensusNode:
    def __init__(self, node_id: int, config: PBFTConfig):
        self.node_id = node_id
        self.config = config
        self.state = PBFTState(node_id, config)
        self.network_queue = asyncio.Queue()
        self.view_change_timer: Optional[asyncio.Task] = None
        self._reset_view_change_timeout()

    def _reset_view_change_timeout(self) -> None:
        if self.view_change_timer:
            self.view_change_timer.cancel()
        self.view_change_timer = asyncio.create_task(
            self._trigger_view_change_after_timeout()
        )

    async def _trigger_view_change_after_timeout(self) -> None:
        await asyncio.sleep(self.config.view_change_timeout)
        await self.initiate_view_change()

    async def initiate_view_change(self) -> None:
        VIEW_CHANGES.inc()
        new_view = self.state.view + 1
        proof = self._collect_view_change_proof()
        
        msg = PBFTMessage(
            type=PBFTMessageType.VIEW_CHANGE,
            view=new_view,
            sequence=0,
            digest=hashlib.sha256(proof).hexdigest(),
            sender=self.node_id
        )
        msg.sign(ED25519_PRIVATE_KEY)
        
        await self.broadcast_message(msg)
        self.state.view = new_view
        ACTIVE_VIEW.set(new_view)

    def _collect_view_change_proof(self) -> bytes:
        # Collects proofs for the last stable checkpoint
        return json.dumps({
            'checkpoint': self.state.last_checkpoint(),
            'log_proof': list(self.state.log.RangeIter(include_value=False))
        }).encode()

    async def broadcast_message(self, message: PBFTMessage) -> None:
        # In production, replace with gRPC streaming
        for node in range(self.config.node_count):
            if node != self.node_id:
                await self.network_queue.put((node, message))

    async def process_message(self, message: PBFTMessage) -> None:
        if not message.verify(self.state.key_store[message.sender]):
            return  # Log security event

        with CONSENSUS_LATENCY.labels(request_type=message.type).time():
            if message.type == PBFTMessageType.REQUEST:
                await self._handle_client_request(message)
            elif message.type == PBFTMessageType.PRE_PREPARE:
                await self._handle_pre_prepare(message)
            elif message.type == PBFTMessageType.PREPARE:
                await self._handle_prepare(message)
            elif message.type == PBFTMessageType.COMMIT:
                await self._handle_commit(message)
            elif message.type == PBFTMessageType.VIEW_CHANGE:
                await self._handle_view_change(message)

    async def _handle_client_request(self, request: PBFTMessage) -> None:
        if not self.is_primary():
            return  # Forward to primary

        if self.state.validate_sequence(request.sequence):
            pre_prepare = PBFTMessage(
                type=PBFTMessageType.PRE_PREPARE,
                view=self.state.view,
                sequence=request.sequence,
                digest=request.digest,
                sender=self.node_id,
                payload=request.payload
            )
            pre_prepare.sign(ED25519_PRIVATE_KEY)
            await self.broadcast_message(pre_prepare)

    async def _handle_pre_prepare(self, message: PBFTMessage) -> None:
        if self._validate_pre_prepare(message):
            prepare = PBFTMessage(
                type=PBFTMessageType.PREPARE,
                view=message.view,
                sequence=message.sequence,
                digest=message.digest,
                sender=self.node_id
            )
            prepare.sign(ED25519_PRIVATE_KEY)
            await self.broadcast_message(prepare)

    def _validate_pre_prepare(self, message: PBFTMessage) -> bool:
        return (self.is_primary(message.sender) and
                message.view == self.state.view and
                self.state.validate_sequence(message.sequence))

    async def _handle_prepare(self, message: PBFTMessage) -> None:
        prepares = self._collect_messages(PBFTMessageType.PREPARE, message)
        if len(prepares) >= 2 * self.config.fault_tolerance:
            commit = PBFTMessage(
                type=PBFTMessageType.COMMIT,
                view=message.view,
                sequence=message.sequence,
                digest=message.digest,
                sender=self.node_id
            )
            commit.sign(ED25519_PRIVATE_KEY)
            await self.broadcast_message(commit)

    async def _handle_commit(self, message: PBFTMessage) -> None:
        commits = self._collect_messages(PBFTMessageType.COMMIT, message)
        if len(commits) >= 2 * self.config.fault_tolerance + 1:
            self._finalize_operation(message.sequence, message.digest)
            self._reset_view_change_timeout()

    def _collect_messages(self, msg_type: int, template: PBFTMessage) -> Set[PBFTMessage]:
        # In production, implement real message aggregation
        return set()  # Simplified for example

    def _finalize_operation(self, sequence: int, digest: str) -> None:
        self.state.committed.add(sequence)
        if sequence % self.config.checkpoint_interval == 0:
            self._create_checkpoint(sequence)

    def _create_checkpoint(self, sequence: int) -> None:
        self.state.checkpoints[sequence] = {
            'state_hash': self._compute_state_hash(),
            'timestamp': datetime.utcnow().isoformat()
        }

    def _compute_state_hash(self) -> str:
        return hashlib.sha256(json.dumps(self.state.log.Stats()).encode()).hexdigest()

    def is_primary(self, node_id: Optional[int] = None) -> bool:
        primary = self.state.view % self.config.node_count
        return (node_id or self.node_id) == primary

# =================================================================
# Enterprise Integration Example
# =================================================================

async def enterprise_consensus_flow():
    config = PBFTConfig(
        node_count=4,
        fault_tolerance=1,
        checkpoint_interval=500,
        request_timeout=15
    )
    
    node = PBFTConsensusNode(0, config)
    
    # Simulate client request
    request = PBFTMessage(
        type=PBFTMessageType.REQUEST,
        view=0,
        sequence=1,
        digest="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        sender=0,
        payload=b'{"action":"update_risk_model"}'
    )
    request.sign(ED25519_PRIVATE_KEY)
    
    await node.process_message(request)

if __name__ == "__main__":
    asyncio.run(enterprise_consensus_flow())
