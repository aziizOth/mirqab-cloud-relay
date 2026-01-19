"""
Mirqab Cloud Relay SDK - Data Models
Data classes for Cloud Relay client operations
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional, Any
import json


class C2ChannelType(Enum):
    """Types of C2 channels available in Cloud Relay"""
    HTTP = "http"
    HTTPS = "https"
    DNS = "dns"
    SMB = "smb"
    CUSTOM = "custom"


class ChannelStatus(Enum):
    """Status of a C2 channel"""
    ACTIVE = "active"
    PAUSED = "paused"
    TERMINATED = "terminated"
    ERROR = "error"


class SessionStatus(Enum):
    """Status of a beacon session"""
    ACTIVE = "active"
    DORMANT = "dormant"
    LOST = "lost"
    TERMINATED = "terminated"


@dataclass
class RelayCredentials:
    """
    Credentials for connecting to Cloud Relay.
    These are returned by Command Center after license activation.
    """
    tenant_id: str
    relay_endpoint: str
    api_token: str
    client_certificate: str
    client_key: str
    ca_certificate: str
    expires_at: datetime
    c2_http_endpoint: str
    c2_dns_domain: str
    payload_upload_url: str

    @classmethod
    def from_dict(cls, data: dict) -> "RelayCredentials":
        """Create credentials from API response dictionary"""
        expires_at = data.get("expires_at")
        if isinstance(expires_at, str):
            expires_at = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))

        return cls(
            tenant_id=data["tenant_id"],
            relay_endpoint=data["relay_endpoint"],
            api_token=data["api_token"],
            client_certificate=data["client_certificate"],
            client_key=data["client_key"],
            ca_certificate=data["ca_certificate"],
            expires_at=expires_at,
            c2_http_endpoint=data["c2_http_endpoint"],
            c2_dns_domain=data["c2_dns_domain"],
            payload_upload_url=data["payload_upload_url"],
        )

    @classmethod
    def from_file(cls, path: str) -> "RelayCredentials":
        """Load credentials from a JSON file"""
        with open(path, "r") as f:
            data = json.load(f)
        return cls.from_dict(data)

    def save_to_file(self, path: str) -> None:
        """Save credentials to a JSON file"""
        data = {
            "tenant_id": self.tenant_id,
            "relay_endpoint": self.relay_endpoint,
            "api_token": self.api_token,
            "client_certificate": self.client_certificate,
            "client_key": self.client_key,
            "ca_certificate": self.ca_certificate,
            "expires_at": self.expires_at.isoformat(),
            "c2_http_endpoint": self.c2_http_endpoint,
            "c2_dns_domain": self.c2_dns_domain,
            "payload_upload_url": self.payload_upload_url,
        }
        with open(path, "w") as f:
            json.dump(data, f, indent=2)

    @property
    def is_expired(self) -> bool:
        """Check if credentials have expired"""
        return datetime.utcnow() > self.expires_at.replace(tzinfo=None)


@dataclass
class C2Channel:
    """
    Represents a C2 communication channel in Cloud Relay.
    """
    channel_id: str
    channel_type: C2ChannelType
    name: str
    endpoint: str
    status: ChannelStatus
    created_at: datetime
    config: dict = field(default_factory=dict)
    active_sessions: int = 0
    total_sessions: int = 0
    bytes_in: int = 0
    bytes_out: int = 0

    @classmethod
    def from_dict(cls, data: dict) -> "C2Channel":
        """Create channel from API response"""
        return cls(
            channel_id=data["channel_id"],
            channel_type=C2ChannelType(data["channel_type"]),
            name=data["name"],
            endpoint=data["endpoint"],
            status=ChannelStatus(data["status"]),
            created_at=datetime.fromisoformat(data["created_at"]),
            config=data.get("config", {}),
            active_sessions=data.get("active_sessions", 0),
            total_sessions=data.get("total_sessions", 0),
            bytes_in=data.get("bytes_in", 0),
            bytes_out=data.get("bytes_out", 0),
        )

    def to_dict(self) -> dict:
        """Convert to dictionary"""
        return {
            "channel_id": self.channel_id,
            "channel_type": self.channel_type.value,
            "name": self.name,
            "endpoint": self.endpoint,
            "status": self.status.value,
            "created_at": self.created_at.isoformat(),
            "config": self.config,
            "active_sessions": self.active_sessions,
            "total_sessions": self.total_sessions,
            "bytes_in": self.bytes_in,
            "bytes_out": self.bytes_out,
        }


@dataclass
class BeaconSession:
    """
    Represents an active beacon session connected to Cloud Relay.
    """
    session_id: str
    channel_id: str
    external_ip: str
    internal_ip: Optional[str]
    hostname: str
    username: str
    os_info: str
    process_info: str
    status: SessionStatus
    first_seen: datetime
    last_seen: datetime
    beacon_interval: int  # seconds
    jitter: int  # percentage
    metadata: dict = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: dict) -> "BeaconSession":
        """Create session from API response"""
        return cls(
            session_id=data["session_id"],
            channel_id=data["channel_id"],
            external_ip=data["external_ip"],
            internal_ip=data.get("internal_ip"),
            hostname=data["hostname"],
            username=data["username"],
            os_info=data["os_info"],
            process_info=data["process_info"],
            status=SessionStatus(data["status"]),
            first_seen=datetime.fromisoformat(data["first_seen"]),
            last_seen=datetime.fromisoformat(data["last_seen"]),
            beacon_interval=data.get("beacon_interval", 60),
            jitter=data.get("jitter", 20),
            metadata=data.get("metadata", {}),
        )

    def to_dict(self) -> dict:
        """Convert to dictionary"""
        return {
            "session_id": self.session_id,
            "channel_id": self.channel_id,
            "external_ip": self.external_ip,
            "internal_ip": self.internal_ip,
            "hostname": self.hostname,
            "username": self.username,
            "os_info": self.os_info,
            "process_info": self.process_info,
            "status": self.status.value,
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "beacon_interval": self.beacon_interval,
            "jitter": self.jitter,
            "metadata": self.metadata,
        }

    @property
    def is_active(self) -> bool:
        """Check if session is still active based on last beacon"""
        timeout = self.beacon_interval * (1 + self.jitter / 100) * 3
        return (datetime.utcnow() - self.last_seen.replace(tzinfo=None)).total_seconds() < timeout


@dataclass
class PayloadInfo:
    """
    Information about a hosted payload in Cloud Relay.
    """
    payload_id: str
    filename: str
    content_type: str
    size_bytes: int
    sha256_hash: str
    download_url: str
    created_at: datetime
    expires_at: Optional[datetime]
    download_count: int = 0
    max_downloads: Optional[int] = None
    metadata: dict = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: dict) -> "PayloadInfo":
        """Create payload info from API response"""
        expires_at = data.get("expires_at")
        if expires_at:
            expires_at = datetime.fromisoformat(expires_at)

        return cls(
            payload_id=data["payload_id"],
            filename=data["filename"],
            content_type=data["content_type"],
            size_bytes=data["size_bytes"],
            sha256_hash=data["sha256_hash"],
            download_url=data["download_url"],
            created_at=datetime.fromisoformat(data["created_at"]),
            expires_at=expires_at,
            download_count=data.get("download_count", 0),
            max_downloads=data.get("max_downloads"),
            metadata=data.get("metadata", {}),
        )

    def to_dict(self) -> dict:
        """Convert to dictionary"""
        return {
            "payload_id": self.payload_id,
            "filename": self.filename,
            "content_type": self.content_type,
            "size_bytes": self.size_bytes,
            "sha256_hash": self.sha256_hash,
            "download_url": self.download_url,
            "created_at": self.created_at.isoformat(),
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "download_count": self.download_count,
            "max_downloads": self.max_downloads,
            "metadata": self.metadata,
        }


@dataclass
class RelayStatus:
    """
    Overall status of the Cloud Relay tenant.
    """
    tenant_id: str
    status: str
    expires_at: datetime
    c2_http_status: str
    c2_dns_status: str
    payload_server_status: str
    total_channels: int
    active_sessions: int
    storage_used_bytes: int
    storage_limit_bytes: int
    last_heartbeat: Optional[datetime] = None

    @classmethod
    def from_dict(cls, data: dict) -> "RelayStatus":
        """Create status from API response"""
        last_heartbeat = data.get("last_heartbeat")
        if last_heartbeat:
            last_heartbeat = datetime.fromisoformat(last_heartbeat)

        return cls(
            tenant_id=data["tenant_id"],
            status=data["status"],
            expires_at=datetime.fromisoformat(data["expires_at"]),
            c2_http_status=data.get("c2_http_status", "unknown"),
            c2_dns_status=data.get("c2_dns_status", "unknown"),
            payload_server_status=data.get("payload_server_status", "unknown"),
            total_channels=data.get("total_channels", 0),
            active_sessions=data.get("active_sessions", 0),
            storage_used_bytes=data.get("storage_used_bytes", 0),
            storage_limit_bytes=data.get("storage_limit_bytes", 0),
            last_heartbeat=last_heartbeat,
        )

    def to_dict(self) -> dict:
        """Convert to dictionary"""
        return {
            "tenant_id": self.tenant_id,
            "status": self.status,
            "expires_at": self.expires_at.isoformat(),
            "c2_http_status": self.c2_http_status,
            "c2_dns_status": self.c2_dns_status,
            "payload_server_status": self.payload_server_status,
            "total_channels": self.total_channels,
            "active_sessions": self.active_sessions,
            "storage_used_bytes": self.storage_used_bytes,
            "storage_limit_bytes": self.storage_limit_bytes,
            "last_heartbeat": self.last_heartbeat.isoformat() if self.last_heartbeat else None,
        }

    @property
    def is_healthy(self) -> bool:
        """Check if all relay services are healthy"""
        return all([
            self.status == "active",
            self.c2_http_status == "healthy",
            self.c2_dns_status == "healthy",
            self.payload_server_status == "healthy",
        ])


@dataclass
class TaskCommand:
    """
    A command to be executed by a beacon session.
    """
    command_id: str
    session_id: str
    command_type: str
    payload: Any
    created_at: datetime
    executed_at: Optional[datetime] = None
    result: Optional[Any] = None
    status: str = "pending"

    @classmethod
    def from_dict(cls, data: dict) -> "TaskCommand":
        return cls(
            command_id=data["command_id"],
            session_id=data["session_id"],
            command_type=data["command_type"],
            payload=data["payload"],
            created_at=datetime.fromisoformat(data["created_at"]),
            executed_at=(
                datetime.fromisoformat(data["executed_at"])
                if data.get("executed_at")
                else None
            ),
            result=data.get("result"),
            status=data.get("status", "pending"),
        )

    def to_dict(self) -> dict:
        return {
            "command_id": self.command_id,
            "session_id": self.session_id,
            "command_type": self.command_type,
            "payload": self.payload,
            "created_at": self.created_at.isoformat(),
            "executed_at": self.executed_at.isoformat() if self.executed_at else None,
            "result": self.result,
            "status": self.status,
        }
