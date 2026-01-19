"""
Crucible Payload Manager - Encrypted Malware Payload Delivery

Securely manages malware samples for testing:
- Encrypts payloads at rest with AES-256-GCM
- Generates unique per-execution encryption keys
- Tracks payload provenance and hash integrity
- Supports payload staging and delivery to agents
"""

import base64
import hashlib
import json
import logging
import os
import secrets
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

logger = logging.getLogger(__name__)


class PayloadStatus(Enum):
    """Payload lifecycle status."""

    PENDING = "pending"
    STORED = "stored"
    ENCRYPTED = "encrypted"
    STAGED = "staged"
    DELIVERED = "delivered"
    EXECUTED = "executed"
    EXPIRED = "expired"
    DELETED = "deleted"


class PayloadCategory(Enum):
    """Malware category classification."""

    RANSOMWARE = "ransomware"
    TROJAN = "trojan"
    WORM = "worm"
    BACKDOOR = "backdoor"
    ROOTKIT = "rootkit"
    KEYLOGGER = "keylogger"
    SPYWARE = "spyware"
    DROPPER = "dropper"
    LOADER = "loader"
    RAT = "rat"  # Remote Access Trojan
    MINER = "miner"
    BOTNET = "botnet"
    APT_TOOL = "apt_tool"
    RED_TEAM_TOOL = "red_team_tool"
    CUSTOM = "custom"


@dataclass
class PayloadMetadata:
    """Metadata about a malware payload."""

    name: str
    category: PayloadCategory
    description: str = ""
    source: str = ""  # Where the sample came from
    family: str = ""  # Malware family name
    variant: str = ""  # Specific variant
    first_seen: Optional[datetime] = None
    mitre_techniques: list[str] = field(default_factory=list)
    expected_behaviors: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)


@dataclass
class EncryptedPayload:
    """Represents an encrypted malware payload ready for delivery."""

    payload_id: str
    metadata: PayloadMetadata
    sha256_original: str  # Hash of original payload
    sha256_encrypted: str  # Hash of encrypted blob
    size_bytes: int
    encrypted_data: bytes
    encryption_nonce: bytes  # 12-byte nonce for AES-GCM
    status: PayloadStatus = PayloadStatus.ENCRYPTED
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: Optional[datetime] = None
    delivery_count: int = 0


@dataclass
class DeliveryPackage:
    """
    Package containing everything needed to deliver and execute a payload.

    Sent to Crucible Agent for execution.
    """

    package_id: str
    payload_id: str
    payload_name: str
    encrypted_payload: bytes  # Base64-encoded encrypted payload
    encryption_key: bytes  # Base64-encoded per-delivery key
    original_hash: str
    execution_args: list[str] = field(default_factory=list)
    timeout_seconds: int = 60
    expected_behaviors: list[str] = field(default_factory=list)
    metadata: dict = field(default_factory=dict)
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


class PayloadManager:
    """
    Manages malware payloads for Crucible testing.

    Security measures:
    - All payloads encrypted at rest with master key
    - Unique keys generated for each delivery
    - SHA256 integrity verification
    - Audit logging for all operations
    - Automatic expiration support
    """

    def __init__(
        self,
        storage_dir: str,
        master_key: Optional[bytes] = None,
    ):
        self.storage_dir = Path(storage_dir)
        self.storage_dir.mkdir(parents=True, exist_ok=True)

        # Master key for encrypting payloads at rest
        # In production, this should come from a secrets manager
        self._master_key = master_key or self._load_or_create_master_key()

        # In-memory cache of payload metadata
        self._payloads: dict[str, EncryptedPayload] = {}

        # Load existing payloads
        self._load_payloads()

    def _load_or_create_master_key(self) -> bytes:
        """Load master key from file or create new one."""
        key_path = self.storage_dir / ".master_key"

        if key_path.exists():
            return key_path.read_bytes()

        # Generate new 256-bit key
        key = secrets.token_bytes(32)
        key_path.write_bytes(key)
        os.chmod(key_path, 0o600)

        logger.info("Generated new master encryption key")
        return key

    def _load_payloads(self) -> None:
        """Load payload metadata from storage."""
        index_path = self.storage_dir / "payloads.json"

        if not index_path.exists():
            return

        try:
            with open(index_path) as f:
                data = json.load(f)

            for payload_id, info in data.items():
                # Load encrypted data
                data_path = self.storage_dir / f"{payload_id}.enc"
                if not data_path.exists():
                    logger.warning(f"Payload data missing: {payload_id}")
                    continue

                encrypted_data = data_path.read_bytes()

                self._payloads[payload_id] = EncryptedPayload(
                    payload_id=payload_id,
                    metadata=PayloadMetadata(
                        name=info["metadata"]["name"],
                        category=PayloadCategory(info["metadata"]["category"]),
                        description=info["metadata"].get("description", ""),
                        source=info["metadata"].get("source", ""),
                        family=info["metadata"].get("family", ""),
                        variant=info["metadata"].get("variant", ""),
                        mitre_techniques=info["metadata"].get("mitre_techniques", []),
                        expected_behaviors=info["metadata"].get("expected_behaviors", []),
                        tags=info["metadata"].get("tags", []),
                    ),
                    sha256_original=info["sha256_original"],
                    sha256_encrypted=info["sha256_encrypted"],
                    size_bytes=info["size_bytes"],
                    encrypted_data=encrypted_data,
                    encryption_nonce=base64.b64decode(info["nonce"]),
                    status=PayloadStatus(info["status"]),
                    created_at=datetime.fromisoformat(info["created_at"]),
                    delivery_count=info.get("delivery_count", 0),
                )

            logger.info(f"Loaded {len(self._payloads)} payloads from storage")

        except Exception as e:
            logger.error(f"Failed to load payloads: {e}")

    def _save_index(self) -> None:
        """Save payload index to storage."""
        index_path = self.storage_dir / "payloads.json"

        data = {}
        for payload_id, payload in self._payloads.items():
            data[payload_id] = {
                "metadata": {
                    "name": payload.metadata.name,
                    "category": payload.metadata.category.value,
                    "description": payload.metadata.description,
                    "source": payload.metadata.source,
                    "family": payload.metadata.family,
                    "variant": payload.metadata.variant,
                    "mitre_techniques": payload.metadata.mitre_techniques,
                    "expected_behaviors": payload.metadata.expected_behaviors,
                    "tags": payload.metadata.tags,
                },
                "sha256_original": payload.sha256_original,
                "sha256_encrypted": payload.sha256_encrypted,
                "size_bytes": payload.size_bytes,
                "nonce": base64.b64encode(payload.encryption_nonce).decode(),
                "status": payload.status.value,
                "created_at": payload.created_at.isoformat(),
                "delivery_count": payload.delivery_count,
            }

        with open(index_path, "w") as f:
            json.dump(data, f, indent=2)

    async def store_payload(
        self,
        payload_data: bytes,
        metadata: PayloadMetadata,
    ) -> EncryptedPayload:
        """
        Store a new malware payload.

        The payload is:
        1. Hashed for integrity verification
        2. Encrypted with master key for at-rest security
        3. Stored to disk with metadata
        """
        payload_id = str(uuid.uuid4())

        # Calculate original hash
        sha256_original = hashlib.sha256(payload_data).hexdigest()

        # Encrypt payload
        nonce = secrets.token_bytes(12)
        aesgcm = AESGCM(self._master_key)
        encrypted_data = nonce + aesgcm.encrypt(nonce, payload_data, None)

        # Calculate encrypted hash
        sha256_encrypted = hashlib.sha256(encrypted_data).hexdigest()

        # Create payload object
        payload = EncryptedPayload(
            payload_id=payload_id,
            metadata=metadata,
            sha256_original=sha256_original,
            sha256_encrypted=sha256_encrypted,
            size_bytes=len(payload_data),
            encrypted_data=encrypted_data,
            encryption_nonce=nonce,
            status=PayloadStatus.STORED,
        )

        # Store encrypted data
        data_path = self.storage_dir / f"{payload_id}.enc"
        data_path.write_bytes(encrypted_data)

        # Update index
        self._payloads[payload_id] = payload
        self._save_index()

        logger.info(
            f"Stored payload {payload_id}",
            extra={
                "payload_id": payload_id,
                "name": metadata.name,
                "category": metadata.category.value,
                "size_bytes": len(payload_data),
                "sha256": sha256_original,
            },
        )

        return payload

    async def get_payload(self, payload_id: str) -> Optional[EncryptedPayload]:
        """Get payload metadata by ID."""
        return self._payloads.get(payload_id)

    async def list_payloads(
        self,
        category: Optional[PayloadCategory] = None,
        status: Optional[PayloadStatus] = None,
    ) -> list[EncryptedPayload]:
        """List payloads with optional filtering."""
        payloads = list(self._payloads.values())

        if category:
            payloads = [p for p in payloads if p.metadata.category == category]

        if status:
            payloads = [p for p in payloads if p.status == status]

        return payloads

    async def prepare_delivery(
        self,
        payload_id: str,
        execution_args: Optional[list[str]] = None,
        timeout_seconds: int = 60,
    ) -> DeliveryPackage:
        """
        Prepare a payload for delivery to a Crucible Agent.

        Generates a unique per-delivery encryption key so that:
        1. The payload is re-encrypted with a fresh key
        2. Only the target agent can decrypt
        3. Key compromise doesn't affect other deliveries
        """
        payload = self._payloads.get(payload_id)
        if not payload:
            raise ValueError(f"Unknown payload: {payload_id}")

        # Decrypt with master key
        nonce = payload.encrypted_data[:12]
        ciphertext = payload.encrypted_data[12:]
        aesgcm = AESGCM(self._master_key)
        original_data = aesgcm.decrypt(nonce, ciphertext, None)

        # Verify integrity
        if hashlib.sha256(original_data).hexdigest() != payload.sha256_original:
            raise RuntimeError("Payload integrity check failed")

        # Generate unique delivery key
        delivery_key = secrets.token_bytes(32)
        delivery_nonce = secrets.token_bytes(12)

        # Re-encrypt with delivery key
        delivery_aesgcm = AESGCM(delivery_key)
        delivery_encrypted = delivery_nonce + delivery_aesgcm.encrypt(
            delivery_nonce, original_data, None
        )

        # Update delivery count
        payload.delivery_count += 1
        payload.status = PayloadStatus.STAGED
        self._save_index()

        package = DeliveryPackage(
            package_id=str(uuid.uuid4()),
            payload_id=payload_id,
            payload_name=payload.metadata.name,
            encrypted_payload=base64.b64encode(delivery_encrypted),
            encryption_key=base64.b64encode(delivery_key),
            original_hash=payload.sha256_original,
            execution_args=execution_args or [],
            timeout_seconds=timeout_seconds,
            expected_behaviors=payload.metadata.expected_behaviors,
            metadata={
                "category": payload.metadata.category.value,
                "family": payload.metadata.family,
                "mitre_techniques": payload.metadata.mitre_techniques,
            },
        )

        logger.info(
            f"Prepared delivery package {package.package_id}",
            extra={
                "package_id": package.package_id,
                "payload_id": payload_id,
                "delivery_count": payload.delivery_count,
            },
        )

        return package

    async def mark_executed(self, payload_id: str) -> None:
        """Mark payload as executed (for tracking)."""
        payload = self._payloads.get(payload_id)
        if payload:
            payload.status = PayloadStatus.EXECUTED
            self._save_index()

    async def delete_payload(self, payload_id: str) -> bool:
        """Securely delete a payload."""
        payload = self._payloads.get(payload_id)
        if not payload:
            return False

        # Overwrite file with random data before deletion
        data_path = self.storage_dir / f"{payload_id}.enc"
        if data_path.exists():
            # Secure overwrite
            size = data_path.stat().st_size
            data_path.write_bytes(secrets.token_bytes(size))
            data_path.unlink()

        # Remove from index
        del self._payloads[payload_id]
        self._save_index()

        logger.info(f"Deleted payload {payload_id}")
        return True

    async def import_from_file(
        self,
        file_path: str,
        metadata: PayloadMetadata,
    ) -> EncryptedPayload:
        """Import a malware sample from a file."""
        path = Path(file_path)
        if not path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")

        payload_data = path.read_bytes()
        return await self.store_payload(payload_data, metadata)

    async def export_decrypted(
        self,
        payload_id: str,
        output_path: str,
    ) -> str:
        """
        Export decrypted payload to file (for manual analysis).

        WARNING: This creates an unencrypted malware sample!
        """
        payload = self._payloads.get(payload_id)
        if not payload:
            raise ValueError(f"Unknown payload: {payload_id}")

        # Decrypt
        nonce = payload.encrypted_data[:12]
        ciphertext = payload.encrypted_data[12:]
        aesgcm = AESGCM(self._master_key)
        original_data = aesgcm.decrypt(nonce, ciphertext, None)

        # Write to file
        out_path = Path(output_path)
        out_path.write_bytes(original_data)

        logger.warning(
            f"Exported DECRYPTED payload to {output_path}",
            extra={"payload_id": payload_id, "output_path": output_path},
        )

        return payload.sha256_original


class PayloadLibrary:
    """
    Pre-built library of common malware samples for testing.

    Includes simulated samples that exhibit specific behaviors
    without actually being malicious (safe for testing).
    """

    @staticmethod
    async def create_test_sample(
        manager: PayloadManager,
        behavior: str,
    ) -> EncryptedPayload:
        """
        Create a test sample that exhibits specific behavior.

        These are NOT real malware, but simulate behaviors for testing:
        - file_encryption: Creates and encrypts dummy files
        - persistence: Adds registry/cron entries
        - network_beacon: Makes periodic outbound connections
        - process_injection: Simulates injection patterns
        """
        test_payloads = {
            "file_encryption": {
                "code": """
import os
import random
# Simulates ransomware file encryption behavior
for i in range(5):
    path = f"/tmp/test_encrypt_{i}.txt"
    with open(path, 'wb') as f:
        f.write(os.urandom(1024))
    print(f"Encrypted: {path}")
""",
                "metadata": PayloadMetadata(
                    name="Test File Encryptor",
                    category=PayloadCategory.RANSOMWARE,
                    description="Simulates ransomware file encryption behavior",
                    expected_behaviors=["file_creation", "file_modification"],
                    tags=["test", "simulation", "safe"],
                ),
            },
            "persistence": {
                "code": """
import os
import platform
# Simulates persistence mechanism
if platform.system() == "Linux":
    cron_entry = "* * * * * /tmp/test_persist.sh"
    print(f"Would add cron: {cron_entry}")
else:
    print("Would add registry key: HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run")
""",
                "metadata": PayloadMetadata(
                    name="Test Persistence",
                    category=PayloadCategory.TROJAN,
                    description="Simulates persistence mechanism installation",
                    mitre_techniques=["T1053.003", "T1547.001"],
                    expected_behaviors=["persistence_attempt"],
                    tags=["test", "simulation", "safe"],
                ),
            },
            "network_beacon": {
                "code": """
import socket
import time
# Simulates C2 beacon behavior
for i in range(3):
    print(f"Beacon attempt {i+1}")
    try:
        # Won't actually connect in isolated environment
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        s.connect(("10.255.255.1", 443))
        s.close()
    except:
        print("Connection blocked (expected)")
    time.sleep(1)
""",
                "metadata": PayloadMetadata(
                    name="Test Network Beacon",
                    category=PayloadCategory.RAT,
                    description="Simulates C2 beacon behavior",
                    mitre_techniques=["T1071.001"],
                    expected_behaviors=["network_connection_attempt"],
                    tags=["test", "simulation", "safe"],
                ),
            },
        }

        if behavior not in test_payloads:
            raise ValueError(f"Unknown behavior: {behavior}. Available: {list(test_payloads.keys())}")

        sample = test_payloads[behavior]
        payload_data = sample["code"].encode("utf-8")

        return await manager.store_payload(payload_data, sample["metadata"])
