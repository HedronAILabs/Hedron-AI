import asyncio
import json
import ssl
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Callable, Awaitable, Set
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.exceptions import InvalidSignature
from prometheus_client import Counter, Gauge, Histogram

# =================================================================
# Security Constants
# =================================================================
RSA_KEY_SIZE = 4096
RAFT_TERM_HASH = hashes.SHA512()
RAFT_PADDING = padding.PSS(
    mgf=padding.MGF1(RAFT_TERM_HASH),
    salt_length=padding.PSS.MAX_LENGTH
)
HEARTBEAT_INTERVAL = 0.5  # 500ms

# =================================================================
# Monitoring Metrics
# =================================================================
LEADER_TERM = Gauge('raft_current_term', 'Current leader term')
COMMIT_INDEX = Gauge('raft_commit_index', 'Highest committed log index')
HEARTBEAT_COUNTER = Counter('raft_heartbeats_total', 'Number of heartbeats sent')
LOG_REPLICATION_DURATION = Histogram('raft_log_replication_seconds', 'Log replication latency')

# =================================================================
# Data Structures
# =================================================================

@dataclass(frozen=True)
class LogEntry:
    term: int
    index: int
    command: bytes
    client_id: str
    signature: bytes

@dataclass(frozen=True)
class AppendEntriesRequest:
    term: int
    leader_id: int
    prev_log_index: int
    prev_log_term: int
    entries: List[LogEntry]
    leader_commit: int
    timestamp: datetime
    auth_token: bytes

@dataclass(frozen=True)
class AppendEntriesResponse:
    term: int
    success: bool
    last_log_index: int
    follower_id: int
    signature: bytes

# =================================================================
# Core Leader Implementation
# =================================================================

class RaftLeader:
    def __init__(
        self,
        node_id: int,
        cluster: Dict[int, str],  # node_id: address
        private_key: rsa.RSAPrivateKey,
        public_keys: Dict[int, rsa.RSAPublicKey],
        ssl_ctx: ssl.SSLContext
    ):
        self.node_id = node_id
        self.cluster = cluster
        self.private_key = private_key
        self.public_keys = public_keys
        self.ssl_ctx = ssl_ctx
        
        # Volatile state
        self.current_term = 0
        self.commit_index = 0
        self.last_applied = 0
        self.next_index: Dict[int, int] = {}
        self.match_index: Dict[int, int] = {}
        
        # Persistent storage
        self.log: List[LogEntry] = []
        self.voted_for: Optional[int] = None
        
        # Async components
        self.heartbeat_task: Optional[asyncio.Task] = None
        self.lock = asyncio.Lock()
        
        # Initialize metrics
        LEADER_TERM.set(0)
        COMMIT_INDEX.set(0)

    # =================================================================
    # Leadership Management
    # =================================================================

    async def start_leadership(self) -> None:
        """Begin leader responsibilities"""
        async with self.lock:
            self.current_term += 1
            LEADER_TERM.set(self.current_term)
            self._initialize_index_tracking()
            
            # Start periodic heartbeat
            self.heartbeat_task = asyncio.create_task(
                self._heartbeat_loop()
            )
            
            # Start log replication manager
            asyncio.create_task(self._log_replication_manager())

    def _initialize_index_tracking(self) -> None:
        """Reset next/match indexes for new term"""
        last_log_index = self.log[-1].index if self.log else 0
        for node in self.cluster:
            self.next_index[node] = last_log_index + 1
            self.match_index[node] = 0

    async def _heartbeat_loop(self) -> None:
        """Maintain leadership through periodic heartbeats"""
        while True:
            await asyncio.sleep(HEARTBEAT_INTERVAL)
            async with self.lock:
                await self._send_heartbeats()
                HEARTBEAT_COUNTER.inc()

    # =================================================================
    # Log Replication
    # =================================================================

    async def _log_replication_manager(self) -> None:
        """Continuous log replication to followers"""
        while True:
            await asyncio.sleep(0.1)  # 100ms replication cycle
            async with self.lock:
                await self._replicate_logs()

    async def _replicate_logs(self) -> None:
        """Push log entries to all followers"""
        tasks = []
        for follower_id in self.cluster:
            if follower_id == self.node_id:
                continue
                
            next_idx = self.next_index[follower_id]
            prev_idx = next_idx - 1
            prev_term = self.log[prev_idx].term if prev_idx >=0 else 0
            
            entries = self.log[next_idx - 1:]  # From next_index onward
            
            request = AppendEntriesRequest(
                term=self.current_term,
                leader_id=self.node_id,
                prev_log_index=prev_idx,
                prev_log_term=prev_term,
                entries=entries,
                leader_commit=self.commit_index,
                timestamp=datetime.utcnow(),
                auth_token=self._generate_auth_token()
            )
            
            tasks.append(
                self._send_append_entries(follower_id, request)
            )
        
        await asyncio.gather(*tasks)

    def _generate_auth_token(self) -> bytes:
        """Create time-bound authentication token"""
        timestamp = datetime.utcnow().isoformat().encode()
        return self.private_key.sign(
            timestamp,
            RAFT_PADDING,
            RAFT_TERM_HASH
        )

    # =================================================================
    # Network Communication
    # =================================================================

    async def _send_heartbeats(self) -> None:
        """Broadcast empty AppendEntries as heartbeat"""
        request = AppendEntriesRequest(
            term=self.current_term,
            leader_id=self.node_id,
            prev_log_index=self.commit_index,
            prev_log_term=self.current_term,
            entries=[],
            leader_commit=self.commit_index,
            timestamp=datetime.utcnow(),
            auth_token=self._generate_auth_token()
        )
        
        tasks = [
            self._send_append_entries(follower_id, request)
            for follower_id in self.cluster if follower_id != self.node_id
        ]
        await asyncio.gather(*tasks)

    async def _send_append_entries(
        self, 
        follower_id: int, 
        request: AppendEntriesRequest
    ) -> None:
        """Secure RPC to follower node with retry logic"""
        start_time = datetime.utcnow()
        max_retries = 3
        success = False
        
        for attempt in range(max_retries):
            try:
                # Enterprise-grade SSL connection
                reader, writer = await asyncio.open_connection(
                    self.cluster[follower_id],
                    ssl=self.ssl_ctx
                )
                
                # Serialize request
                data = json.dumps({
                    "term": request.term,
                    "leader_id": request.leader_id,
                    "prev_log_index": request.prev_log_index,
                    "prev_log_term": request.prev_log_term,
                    "entries": [
                        {
                            "term": entry.term,
                            "index": entry.index,
                            "command": entry.command.decode(),
                            "client_id": entry.client_id,
                            "signature": entry.signature.hex()
                        } for entry in request.entries
                    ],
                    "leader_commit": request.leader_commit,
                    "timestamp": request.timestamp.isoformat(),
                    "auth_token": request.auth_token.hex()
                }).encode()
                
                # Send request
                writer.write(data)
                await writer.drain()
                
                # Get response
                response_data = await reader.read(4096)
                response = json.loads(response_data.decode())
                
                # Validate response signature
                if self._validate_response_signature(response):
                    success = True
                    break
                    
            except (ConnectionError, TimeoutError, InvalidSignature) as e:
                await asyncio.sleep(2 ** attempt)  # Exponential backoff
            finally:
                if 'writer' in locals():
                    writer.close()
                    await writer.wait_closed()
        
        duration = (datetime.utcnow() - start_time).total_seconds()
        LOG_REPLICATION_DURATION.observe(duration)
        
        if success:
            await self._handle_successful_response(follower_id, response)
        else:
            await self._handle_failed_replication(follower_id)

    def _validate_response_signature(self, response: dict) -> bool:
        """Verify cryptographic signature of follower response"""
        try:
            public_key = self.public_keys[response['follower_id']]
            signature = bytes.fromhex(response['signature'])
            data = f"{response['term']}:{response['success']}".encode()
            
            public_key.verify(
                signature,
                data,
                RAFT_PADDING,
                RAFT_TERM_HASH
            )
            return True
        except (InvalidSignature, KeyError):
            return False

    # =================================================================
    # Response Handling
    # =================================================================

    async def _handle_successful_response(
        self,
        follower_id: int,
        response: dict
    ) -> None:
        """Update replication state based on follower response"""
        async with self.lock:
            if response['term'] > self.current_term:
                await self._step_down(response['term'])
                return
                
            if response['success']:
                self.next_index[follower_id] = response['last_log_index'] + 1
                self.match_index[follower_id] = response['last_log_index']
                await self._update_commit_index()
            else:
                self.next_index[follower_id] -= 1

    async def _update_commit_index(self) -> None:
        """Advance commit index based on majority replication"""
        match_indices = sorted(self.match_index.values())
        new_commit_index = match_indices[len(match_indices) // 2]
        
        if new_commit_index > self.commit_index:
            self.commit_index = new_commit_index
            COMMIT_INDEX.set(new_commit_index)
            await self._apply_committed_entries()

    async def _apply_committed_entries(self) -> None:
        """Apply committed entries to state machine (enterprise integration point)"""
        entries_to_apply = self.log[self.last_applied:self.commit_index]
        # Integration with enterprise state machine would occur here
        self.last_applied = self.commit_index

    # =================================================================
    # Leadership Transition
    # =================================================================

    async def _step_down(self, new_term: int) -> None:
        """Relinquish leadership upon term update"""
        async with self.lock:
            self.current_term = new_term
            LEADER_TERM.set(new_term)
            
            if self.heartbeat_task:
                self.heartbeat_task.cancel()
            
            # Transition to follower state
            # (Implementation would trigger state change callback)

    async def _handle_failed_replication(self, follower_id: int) -> None:
        """Handle persistent replication failures (enterprise alerting integration)"""
        # Implementation would integrate with enterprise monitoring systems
        pass

# =================================================================
# Enterprise SSL Configuration Example
# =================================================================

def create_enterprise_ssl_context() -> ssl.SSLContext:
    """Configure military-grade TLS 1.3 settings"""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.options |= ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3 | ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.set_ciphers('TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256')
    ctx.verify_mode = ssl.CERT_REQUIRED
    return ctx

# =================================================================
# Enterprise Usage Example
# =================================================================

async def main():
    # Generate cluster keys
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=RSA_KEY_SIZE
    )
    public_keys = {
        1: private_key.public_key(),
        2: rsa.generate_private_key(65537, RSA_KEY_SIZE).public_key(),
        3: rsa.generate_private_key(65537, RSA_KEY_SIZE).public_key()
    }
    
    # Create SSL context
    ssl_ctx = create_enterprise_ssl_context()
    
    # Initialize leader node
    leader = RaftLeader(
        node_id=1,
        cluster={1: "node1.hedron.ai:21000", 2: "node2.hedron.ai:21000"},
        private_key=private_key,
        public_keys=public_keys,
        ssl_ctx=ssl_ctx
    )
    
    # Start leadership
    await leader.start_leadership()

if __name__ == "__main__":
    asyncio.run(main())
