"""Pydantic schemas for Payload Service API."""
from datetime import datetime
from typing import Optional
from uuid import UUID

from pydantic import BaseModel, Field

from .models import PayloadCategory, SafetyLevel, DownloadResult


class PayloadResponse(BaseModel):
    """Payload metadata response."""
    id: UUID
    name: str
    filename: str
    category: PayloadCategory
    subcategory: Optional[str] = None
    mime_type: str
    file_size: int
    sha256: str
    description: Optional[str] = None
    mitre_technique_id: Optional[str] = None
    expected_detection: Optional[str] = None
    safety_level: SafetyLevel
    enabled: bool
    created_at: datetime
    download_url: str

    class Config:
        from_attributes = True


class PayloadListResponse(BaseModel):
    """List of payloads response."""
    total: int
    items: list[PayloadResponse]


class PayloadRequestLogResponse(BaseModel):
    """Payload request log response."""
    id: UUID
    payload_id: Optional[UUID] = None
    tenant_id: Optional[str] = None
    agent_id: Optional[str] = None
    source_ip: Optional[str] = None
    result: DownloadResult
    response_code: Optional[int] = None
    requested_at: datetime

    class Config:
        from_attributes = True


class PayloadStatsResponse(BaseModel):
    """Payload download statistics."""
    payload_id: UUID
    filename: str
    total_downloads: int
    successful_downloads: int
    blocked_downloads: int
    unique_agents: int
    last_download: Optional[datetime] = None


class HealthResponse(BaseModel):
    """Health check response."""
    status: str = Field(default="healthy")
    service: str = Field(default="payload-service")
    version: str
    database: str = Field(default="connected")
    payloads_count: int = Field(default=0)
