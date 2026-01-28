"""
Cloud Relay API Gateway - Data Models
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any


class TenantTier(str, Enum):
    TRIAL = "trial"
    STARTER = "starter"
    PROFESSIONAL = "professional"
    ENTERPRISE = "enterprise"


@dataclass
class TierLimits:
    """Rate limits and quotas per tenant tier."""
    max_agents: int
    concurrent_tasks: int
    requests_per_hour: int
    cpu_limit: str
    memory_limit: str
    allowed_features: list[str] = field(default_factory=list)


# Tier configuration
TIER_LIMITS: dict[TenantTier, TierLimits] = {
    TenantTier.TRIAL: TierLimits(
        max_agents=3,
        concurrent_tasks=5,
        requests_per_hour=100,
        cpu_limit="500m",
        memory_limit="512Mi",
        allowed_features=["waf", "c2_http"],
    ),
    TenantTier.STARTER: TierLimits(
        max_agents=10,
        concurrent_tasks=20,
        requests_per_hour=1000,
        cpu_limit="1",
        memory_limit="1Gi",
        allowed_features=["waf", "c2_http", "c2_dns", "payload"],
    ),
    TenantTier.PROFESSIONAL: TierLimits(
        max_agents=50,
        concurrent_tasks=100,
        requests_per_hour=10000,
        cpu_limit="4",
        memory_limit="4Gi",
        allowed_features=["waf", "c2_http", "c2_dns", "payload", "phishing"],
    ),
    TenantTier.ENTERPRISE: TierLimits(
        max_agents=10000,  # Effectively unlimited
        concurrent_tasks=500,
        requests_per_hour=100000,
        cpu_limit="16",
        memory_limit="16Gi",
        allowed_features=["waf", "c2_http", "c2_dns", "payload", "phishing", "custom"],
    ),
}


@dataclass
class Tenant:
    """Tenant configuration."""
    id: str
    name: str
    tier: TenantTier
    api_key: str
    api_secret: str
    active: bool = True
    created_at: datetime = field(default_factory=datetime.utcnow)
    callback_url: str | None = None
    allowed_ips: list[str] = field(default_factory=list)


@dataclass
class RateLimitResult:
    """Result of rate limit check."""
    allowed: bool
    remaining: int = 0
    reset_at: float = 0
    retry_after: int = 0


@dataclass
class QuotaResult:
    """Result of quota enforcement check."""
    allowed: bool
    reason: str = ""
    retry_after: int = 0


@dataclass
class AuthResult:
    """Result of authentication."""
    authenticated: bool
    tenant: Tenant | None = None
    error: str = ""


@dataclass
class RequestContext:
    """Validated request context."""
    tenant_id: str
    tenant: Tenant
    request_id: str
    correlation_id: str
    timestamp: datetime
    nonce: str
    source_ip: str
    user_agent: str
    rate_limit_remaining: int = 0


@dataclass
class AuditEvent:
    """Audit log event."""
    timestamp: datetime
    event_type: str
    tenant_id: str
    request_id: str
    correlation_id: str
    source_ip: str
    user_agent: str
    endpoint: str
    method: str
    status_code: int
    duration_ms: int
    details: dict[str, Any] = field(default_factory=dict)
