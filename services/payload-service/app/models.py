"""Database models for Payload Service."""
from datetime import datetime
from enum import Enum
from uuid import uuid4

from sqlalchemy import (
    Column,
    String,
    Integer,
    Boolean,
    DateTime,
    Text,
    ForeignKey,
    Index,
    Enum as SQLAEnum,
)
from sqlalchemy.dialects.postgresql import UUID, INET
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship

Base = declarative_base()


class PayloadCategory(str, Enum):
    """Payload category types."""
    EXECUTABLE = "executable"
    SCRIPT = "script"
    DOCUMENT = "document"
    ARCHIVE = "archive"
    DISGUISED = "disguised"


class SafetyLevel(str, Enum):
    """Payload safety levels."""
    SAFE = "safe"  # EICAR test strings - universally detected
    SIGNATURE = "signature"  # Known malware signatures - non-functional
    BEHAVIORAL = "behavioral"  # Behavioral patterns - may trigger heuristics


class DownloadResult(str, Enum):
    """Download result status."""
    DOWNLOADED = "downloaded"
    BLOCKED = "blocked"
    TIMEOUT = "timeout"
    ERROR = "error"


class Payload(Base):
    """Payload metadata table."""
    __tablename__ = "payloads"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid4)
    name = Column(String(255), nullable=False)
    filename = Column(String(255), nullable=False, unique=True)
    category = Column(SQLAEnum(PayloadCategory), nullable=False)
    subcategory = Column(String(50), nullable=True)
    file_path = Column(String(512), nullable=False)
    mime_type = Column(String(100), nullable=False)
    file_size = Column(Integer, nullable=False)
    sha256 = Column(String(64), nullable=False)
    description = Column(Text, nullable=True)
    mitre_technique_id = Column(String(20), nullable=True)
    expected_detection = Column(String(100), nullable=True)  # av, proxy, sandbox, edr
    safety_level = Column(SQLAEnum(SafetyLevel), default=SafetyLevel.SAFE)
    enabled = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    requests = relationship("PayloadRequest", back_populates="payload")

    def __repr__(self):
        return f"<Payload {self.filename}>"


class PayloadRequest(Base):
    """Payload download request logging table."""
    __tablename__ = "payload_requests"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid4)
    payload_id = Column(UUID(as_uuid=True), ForeignKey("payloads.id"), nullable=True)
    tenant_id = Column(String(64), nullable=True)
    agent_id = Column(String(128), nullable=True)
    source_ip = Column(INET, nullable=True)
    user_agent = Column(String(512), nullable=True)
    result = Column(SQLAEnum(DownloadResult), default=DownloadResult.DOWNLOADED)
    response_code = Column(Integer, nullable=True)
    blocked_by = Column(String(100), nullable=True)
    execution_id = Column(Integer, nullable=True)
    requested_at = Column(DateTime, default=datetime.utcnow)
    response_time_ms = Column(Integer, nullable=True)

    # Relationships
    payload = relationship("Payload", back_populates="requests")

    __table_args__ = (
        Index("idx_payload_requests_tenant", "tenant_id"),
        Index("idx_payload_requests_time", "requested_at"),
        Index("idx_payload_requests_payload", "payload_id"),
    )

    def __repr__(self):
        return f"<PayloadRequest {self.id}>"
