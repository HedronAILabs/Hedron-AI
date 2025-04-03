import json
import hashlib
from dataclasses import dataclass
from datetime import datetime
from typing import Dict, Optional, Any, List, Tuple
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.exceptions import InvalidSignature
from prometheus_client import Counter, Histogram

# =================================================================
# Security Constants
# =================================================================
RSA_KEY_SIZE = 4096
SIGNATURE_HASH = hashes.SHA512()
PADDING_SCHEME = padding.PSS(
    mgf=padding.MGF1(SIGNATURE_HASH),
    salt_length=padding.PSS.MAX_LENGTH
)

# =================================================================
# Prometheus Metrics
# =================================================================
MESSAGE_VALIDATION_TIME = Histogram(
    'pbft_message_validation_seconds',
    'Time spent validating message signatures',
    ['message_type']
)

INVALID_MESSAGES = Counter(
    'pbft_invalid_messages_total',
    'Total rejected messages',
    ['reason']
)

# =================================================================
# Core Message Types
# =================================================================

class MessageType:
    CLIENT_REQUEST = 0x01
    PRE_PREPARE = 0x02
    PREPARE = 0x03
    COMMIT = 0x04
    VIEW_CHANGE = 0x05
    NEW_VIEW = 0x06

@dataclass(frozen=True)
class MessageHeader:
    protocol_version: int = 1
    message_type: int
    view_number: int
    sequence_number: int
    sender_id: int
    timestamp: float = datetime.utcnow().timestamp()

    def serialize(self) -> bytes:
        return json.dumps({
            'protocol': self.protocol_version,
            'type': self.message_type,
            'view': self.view_number,
            'seq': self.sequence_number,
            'sender': self.sender_id,
            'ts': self.timestamp
        }).encode()

@dataclass
class ClientRequest:
    operation: bytes
    client_id: str
    signature: Optional[bytes] = None

    def content_hash(self) -> str:
        return hashlib.sha3_256(
            self.operation + self.client_id.encode()
        ).hexdigest()

@dataclass
class PrePrepare:
    request: ClientRequest
    batch_hash: str
    replica_sig: Optional[bytes] = None

@dataclass
class Prepare:
    digest: str
    replica_sig: Optional[bytes] = None

@dataclass
class Commit:
    digest: str
    replica_sig: Optional[bytes] = None

@dataclass
class ViewChangeProof:
    checkpoint_seq: int
    checkpoint_hash: str
    message_set: List[Tuple[int, str]]  # (sequence, digest)

@dataclass
class ViewChange:
    new_view: int
    proof: ViewChangeProof
    replica_sig: Optional[bytes] = None

@dataclass
class NewView:
    view_change_proofs: List[ViewChange]
    pre_prepares: List[PrePrepare]
    replica_sig: Optional[bytes] = None

# =================================================================
# Message Container with Full Validation
# =================================================================

class PBFTMessage:
    def __init__(
        self,
        header: MessageHeader,
        body: Any,
        public_key: rsa.RSAPublicKey
    ):
        self.header = header
        self.body = body
        self.public_key = public_key
        self._digest_cache = None

    @property
    def message_digest(self) -> str:
        if not self._digest_cache:
            self._digest_cache = hashlib.sha3_256(
                self.header.serialize() +
                self._serialize_body()
            ).hexdigest()
        return self._digest_cache

    def _serialize_body(self) -> bytes:
        if isinstance(self.body, ClientRequest):
            return self.body.operation + self.body.client_id.encode()
        # Add serialization for other types
        return b''

    def validate(self) -> Tuple[bool, List[str]]:
        errors = []
        valid = True

        # 1. Protocol Version Check
        if self.header.protocol_version != 1:
            errors.append("Unsupported protocol version")
            valid = False

        # 2. Temporal Validity Window (300ms)
        if abs(datetime.utcnow().timestamp() - self.header.timestamp) > 0.3:
            errors.append("Message timestamp outside validity window")
            valid = False

        # 3. Cryptographic Signature Verification
        with MESSAGE_VALIDATION_TIME.labels(
            message_type=self.header.message_type
        ).time():
            if not self._verify_signature():
                errors.append("Invalid cryptographic signature")
                valid = False

        # 4. Message Type-Specific Validation
        type_validator = {
            MessageType.CLIENT_REQUEST: self._validate_client_request,
            MessageType.PRE_PREPARE: self._validate_pre_prepare,
            # Add other validators
        }.get(self.header.message_type, lambda: (True, []))
        
        type_valid, type_errors = type_validator()
        valid &= type_valid
        errors.extend(type_errors)

        return valid, errors

    def _verify_signature(self) -> bool:
        try:
            if self.header.message_type == MessageType.CLIENT_REQUEST:
                self.public_key.verify(
                    self.body.signature,
                    self.body.operation,
                    PADDING_SCHEME,
                    SIGNATURE_HASH
                )
            elif self.header.message_type in [
                MessageType.PRE_PREPARE,
                MessageType.PREPARE,
                MessageType.COMMIT
            ]:
                self.public_key.verify(
                    self.body.replica_sig,
                    self.message_digest.encode(),
                    PADDING_SCHEME,
                    SIGNATURE_HASH
                )
            return True
        except InvalidSignature:
            return False

    def _validate_client_request(self) -> Tuple[bool, List[str]]:
        errors = []
        if len(self.body.operation) > 1_000_000:  # 1MB limit
            errors.append("Operation payload exceeds size limit")
        return len(errors) == 0, errors

    def _validate_pre_prepare(self) -> Tuple[bool, List[str]]:
        errors = []
        if self.body.batch_hash != self.body.request.content_hash():
            errors.append("Batch hash mismatch in PrePrepare")
        return len(errors) == 0, errors

# =================================================================
# Message Factory with Caching
# =================================================================

class MessageFactory:
    _key_cache: Dict[int, rsa.RSAPublicKey] = {}

    @classmethod
    def create_client_request(
        cls,
        client_id: str,
        operation: bytes,
        private_key: rsa.RSAPrivateKey
    ) -> PBFTMessage:
        request = ClientRequest(operation, client_id)
        signature = private_key.sign(
            operation,
            PADDING_SCHEME,
            SIGNATURE_HASH
        )
        request.signature = signature
        
        header = MessageHeader(
            message_type=MessageType.CLIENT_REQUEST,
            view_number=0,  # Client requests don't have view context
            sequence_number=0,
            sender_id=int(client_id)
        )
        
        return PBFTMessage(
            header,
            request,
            private_key.public_key()
        )

    @classmethod
    def from_network(
        cls,
        raw_data: bytes,
        node_id: int
    ) -> Optional[PBFTMessage]:
        try:
            parsed = json.loads(raw_data)
            header_data = parsed['header']
            body_data = parsed['body']
            
            header = MessageHeader(**header_data)
            public_key = cls._get_public_key(header.sender_id)
            
            body = cls._deserialize_body(header.message_type, body_data)
            
            return PBFTMessage(header, body, public_key)
        except (KeyError, TypeError, ValueError) as e:
            INVALID_MESSAGES.labels(reason='deserialization').inc()
            return None

    @classmethod
    def _deserialize_body(cls, msg_type: int, data: dict) -> Any:
        deserializers = {
            MessageType.CLIENT_REQUEST: lambda d: ClientRequest(
                operation=bytes.fromhex(d['operation']),
                client_id=d['client_id'],
                signature=bytes.fromhex(d['signature'])
            ),
            # Add other deserializers
        }
        return deserializers.get(msg_type, lambda _: None)(data)

    @classmethod
    def _get_public_key(cls, node_id: int) -> rsa.RSAPublicKey:
        if node_id not in cls._key_cache:
            # In production, fetch from HSM or key management service
            cls._key_cache[node_id] = rsa.generate_private_key(
                public_exponent=65537,
                key_size=RSA_KEY_SIZE
            ).public_key()
        return cls._key_cache[node_id]

# =================================================================
# Enterprise Usage Example
# =================================================================

if __name__ == "__main__":
    # Generate client keys
    client_priv_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=RSA_KEY_SIZE
    )
    client_pub_key = client_priv_key.public_key()

    # Create sample client request
    request = MessageFactory.create_client_request(
        client_id="trade-789",
        operation=b'{"action":"execute_order","qty":100}',
        private_key=client_priv_key
    )

    # Serialize for network transmission
    network_payload = json.dumps({
        "header": {
            "protocol_version": request.header.protocol_version,
            "message_type": request.header.message_type,
            "view_number": request.header.view_number,
            "sequence_number": request.header.sequence_number,
            "sender_id": request.header.sender_id,
            "timestamp": request.header.timestamp
        },
        "body": {
            "operation": request.body.operation.hex(),
            "client_id": request.body.client_id,
            "signature": request.body.signature.hex()
        }
    }).encode()

    # Deserialize on receiving node
    received_message = MessageFactory.from_network(
        network_payload,
        node_id=0
    )

    # Validate message
    if received_message:
        is_valid, errors = received_message.validate()
        print(f"Message valid: {is_valid}, Errors: {errors}")
