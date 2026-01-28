# Cloud Relay Production Requirements

## Overview

Cloud Relay is a multi-tenant attack platform deployed on public cloud (AWS/Azure/GCP) that serves multiple OffenSight customers simultaneously. All attack execution is controlled by the customer's Master Server (OffenSight instance).

---

## Architecture

```
                            PUBLIC CLOUD (Single Instance)
┌─────────────────────────────────────────────────────────────────────────────┐
│                                                                              │
│                         CLOUD RELAY CLUSTER                                  │
│  ┌────────────────────────────────────────────────────────────────────────┐ │
│  │                        API GATEWAY                                      │ │
│  │  • mTLS termination & tenant extraction                                │ │
│  │  • Rate limiting (per-tenant)                                          │ │
│  │  • Request validation (nonce, timestamp, signature)                    │ │
│  │  • Quota enforcement                                                   │ │
│  └────────────────────────────────────────────────────────────────────────┘ │
│                                    │                                         │
│         ┌──────────────────────────┼──────────────────────────┐             │
│         ▼                          ▼                          ▼             │
│  ┌─────────────┐          ┌─────────────┐          ┌─────────────┐         │
│  │   HTTP-C2   │          │  WAF-Tester │          │   Payload   │         │
│  │   Service   │          │   Service   │          │   Server    │         │
│  └─────────────┘          └─────────────┘          └─────────────┘         │
│         │                          │                          │             │
│         └──────────────────────────┴──────────────────────────┘             │
│                                    │                                         │
│                              ┌─────▼─────┐                                  │
│                              │   Redis   │  (Task Queue + Rate Limits)      │
│                              └───────────┘                                  │
│                                                                              │
└──────────────────────────────────────────────────────────────────────────────┘
                                    │
            ┌───────────────────────┼───────────────────────┐
            ▼                       ▼                       ▼
┌───────────────────┐   ┌───────────────────┐   ┌───────────────────┐
│  CUSTOMER A       │   │  CUSTOMER B       │   │  CUSTOMER C       │
│  (On-Premise)     │   │  (On-Premise)     │   │  (On-Premise)     │
│                   │   │                   │   │                   │
│  ┌─────────────┐  │   │  ┌─────────────┐  │   │  ┌─────────────┐  │
│  │ OffenSight  │  │   │  │ OffenSight  │  │   │  │ OffenSight  │  │
│  │   Master    │──┼───┼──│   Master    │──┼───┼──│   Master    │  │
│  └─────────────┘  │   │  └─────────────┘  │   │  └─────────────┘  │
│                   │   │                   │   │                   │
│  ┌─────────────┐  │   │  ┌─────────────┐  │   │  ┌─────────────┐  │
│  │   Agents    │  │   │  │   Agents    │  │   │  │   Agents    │  │
│  └─────────────┘  │   │  └─────────────┘  │   │  └─────────────┘  │
└───────────────────┘   └───────────────────┘   └───────────────────┘
```

---

## Core Requirements

### 1. Multi-Tenant Isolation

| Requirement | Implementation | Status |
|-------------|----------------|--------|
| Tenant ID in all requests | X-Tenant-ID header + mTLS cert extraction | Partial |
| Data isolation | Tenant ID foreign key on all tables | Done |
| Network isolation | Per-tenant NetworkPolicy (Kubernetes) | Done |
| Resource quotas | Per-tier limits (CPU, memory, requests) | Partial |
| Rate limiting | Per-tenant request limits | Pending |

### 2. Authentication & Authorization

| Requirement | Implementation | Status |
|-------------|----------------|--------|
| mTLS authentication | Client certificates per tenant | Done |
| API key validation | X-API-Key header verification | Done |
| Request signing | HMAC-SHA256 signature validation | Done |
| Nonce validation | Prevent replay attacks | Pending |
| Timestamp validation | Reject old requests (>5 min) | Pending |

### 3. Master Server Control

| Requirement | Implementation | Status |
|-------------|----------------|--------|
| Task dispatch | POST /api/v1/tasks | Done |
| Result callback | POST to Master's callback URL | Done |
| Kill switch | POST /api/v1/c2/kill-all | Done |
| Execution control | Master specifies all parameters | Done |

### 4. Security Hardening

| Requirement | Implementation | Status |
|-------------|----------------|--------|
| TLS 1.3 minimum | Ingress configuration | Pending |
| Request validation | Schema + signature + nonce | Pending |
| Audit logging | Structured logs with tenant context | Partial |
| Secrets management | External secrets store integration | Pending |
| DDoS protection | Cloud WAF + rate limiting | Pending |

---

## Tenant Tiers & Quotas

| Tier | Max Agents | Concurrent Tasks | Requests/Hour | CPU | Memory |
|------|------------|------------------|---------------|-----|--------|
| TRIAL | 3 | 5 | 100 | 0.5 | 512Mi |
| STARTER | 10 | 20 | 1,000 | 1 | 1Gi |
| PROFESSIONAL | 50 | 100 | 10,000 | 4 | 4Gi |
| ENTERPRISE | Unlimited | 500 | 100,000 | 16 | 16Gi |

---

## API Gateway Requirements

### Request Flow

```
1. TLS Termination
   └─► Extract client certificate
   └─► Verify against tenant CA

2. Tenant Identification
   └─► Extract tenant_id from cert CN
   └─► Verify X-Tenant-ID header matches
   └─► Load tenant configuration

3. Authentication
   └─► Validate X-API-Key header
   └─► Verify request signature (HMAC-SHA256)
   └─► Check nonce (not used before)
   └─► Validate timestamp (within 5 minutes)

4. Authorization
   └─► Check tenant tier permissions
   └─► Verify endpoint access allowed

5. Rate Limiting
   └─► Check requests/hour quota
   └─► Check concurrent tasks quota
   └─► Return 429 if exceeded

6. Request Forwarding
   └─► Add X-Verified-Tenant-ID header
   └─► Forward to appropriate service
   └─► Log request with correlation ID
```

### Security Headers

```python
# Required headers for all requests
X-Tenant-ID: str           # Tenant identifier
X-API-Key: str             # API key for tenant
X-Request-Signature: str   # HMAC-SHA256(request_body + timestamp + nonce)
X-Request-Timestamp: str   # ISO8601 timestamp
X-Request-Nonce: str       # Unique request identifier (UUID)

# Optional headers
X-Correlation-ID: str      # For request tracing
X-Forwarded-For: str       # Original client IP
```

### Signature Validation

```python
def validate_signature(request):
    # 1. Extract components
    body = request.body
    timestamp = request.headers["X-Request-Timestamp"]
    nonce = request.headers["X-Request-Nonce"]
    signature = request.headers["X-Request-Signature"]

    # 2. Validate timestamp (within 5 minutes)
    request_time = datetime.fromisoformat(timestamp)
    if abs((datetime.utcnow() - request_time).total_seconds()) > 300:
        raise HTTPException(401, "Request timestamp expired")

    # 3. Check nonce not reused
    if redis.exists(f"nonce:{nonce}"):
        raise HTTPException(401, "Nonce already used")
    redis.setex(f"nonce:{nonce}", 600, "1")  # Store for 10 minutes

    # 4. Validate signature
    payload = f"{body}|{timestamp}|{nonce}"
    expected = hmac.new(
        tenant.api_secret.encode(),
        payload.encode(),
        hashlib.sha256
    ).hexdigest()

    if not hmac.compare_digest(signature, expected):
        raise HTTPException(401, "Invalid signature")
```

---

## Rate Limiting Implementation

### Redis-Based Distributed Rate Limiting

```python
class RateLimiter:
    def __init__(self, redis_client):
        self.redis = redis_client

    async def check_rate_limit(
        self,
        tenant_id: str,
        tier: TenantTier,
    ) -> RateLimitResult:
        """
        Check if request is within rate limits.
        Uses sliding window algorithm.
        """
        now = time.time()
        window_start = now - 3600  # 1 hour window

        key = f"rate:{tenant_id}:requests"

        # Remove old entries
        await self.redis.zremrangebyscore(key, 0, window_start)

        # Count current requests
        current_count = await self.redis.zcard(key)

        # Get tier limit
        limit = TIER_LIMITS[tier].requests_per_hour

        if current_count >= limit:
            return RateLimitResult(
                allowed=False,
                remaining=0,
                reset_at=window_start + 3600,
                retry_after=int(window_start + 3600 - now),
            )

        # Add current request
        await self.redis.zadd(key, {str(uuid4()): now})
        await self.redis.expire(key, 3600)

        return RateLimitResult(
            allowed=True,
            remaining=limit - current_count - 1,
            reset_at=window_start + 3600,
        )

    async def check_concurrent_tasks(
        self,
        tenant_id: str,
        tier: TenantTier,
    ) -> bool:
        """Check if tenant can start a new concurrent task."""
        key = f"tasks:{tenant_id}:active"
        current = await self.redis.scard(key)
        limit = TIER_LIMITS[tier].concurrent_tasks
        return current < limit
```

---

## Quota Enforcement

### Pre-Execution Validation

```python
async def enforce_quota(
    tenant_id: str,
    task_type: str,
    db: Session,
    redis: Redis,
) -> QuotaResult:
    """
    Enforce all quotas before task execution.
    Called by API gateway before forwarding request.
    """
    # 1. Load tenant configuration
    tenant = db.query(Tenant).filter(Tenant.id == tenant_id).first()
    if not tenant:
        return QuotaResult(allowed=False, reason="Tenant not found")

    if not tenant.active:
        return QuotaResult(allowed=False, reason="Tenant suspended")

    # 2. Check tier limits
    tier = TenantTier(tenant.tier)
    limits = TIER_LIMITS[tier]

    # 3. Check rate limit
    rate_result = await rate_limiter.check_rate_limit(tenant_id, tier)
    if not rate_result.allowed:
        return QuotaResult(
            allowed=False,
            reason="Rate limit exceeded",
            retry_after=rate_result.retry_after,
        )

    # 4. Check concurrent tasks
    if not await rate_limiter.check_concurrent_tasks(tenant_id, tier):
        return QuotaResult(
            allowed=False,
            reason="Concurrent task limit exceeded",
        )

    # 5. Check feature access
    if task_type not in limits.allowed_features:
        return QuotaResult(
            allowed=False,
            reason=f"Feature '{task_type}' not available in {tier.value} tier",
        )

    return QuotaResult(allowed=True)
```

---

## Audit Logging

### Structured Log Format

```python
{
    "timestamp": "2026-01-27T20:00:00.000Z",
    "level": "INFO",
    "logger": "cloud-relay.api",
    "event": "task_executed",

    # Request context
    "request_id": "req-abc123",
    "correlation_id": "corr-xyz789",

    # Tenant context (REQUIRED for all logs)
    "tenant_id": "acme-corp",
    "tenant_tier": "professional",

    # Task details
    "task_id": "task-001",
    "task_type": "waf",
    "execution_id": "exec-12345",

    # Result
    "status": "completed",
    "duration_ms": 1234,

    # Security
    "source_ip": "203.0.113.50",
    "user_agent": "OffenSight-Master/1.0",
}
```

### Log Retention

| Log Type | Retention | Storage |
|----------|-----------|---------|
| Access logs | 90 days | Cloud Storage (GCS/S3) |
| Audit logs | 1 year | Cloud Storage + BigQuery |
| Error logs | 30 days | Cloud Logging |
| Security events | 2 years | SIEM integration |

---

## Deployment Checklist

### Pre-Production

- [ ] API gateway implemented with all security checks
- [ ] Rate limiting tested under load
- [ ] Quota enforcement validated
- [ ] mTLS certificate validation working
- [ ] Request signing validated
- [ ] Nonce/timestamp validation implemented
- [ ] Audit logging with tenant context
- [ ] Secrets in external vault (not env vars)
- [ ] Network policies applied
- [ ] Resource quotas configured

### Production Readiness

- [ ] TLS 1.3 enforced
- [ ] WAF rules configured
- [ ] DDoS protection enabled
- [ ] Monitoring dashboards created
- [ ] Alerting configured
- [ ] Backup procedures tested
- [ ] DR plan documented
- [ ] Runbooks created
- [ ] Load testing completed
- [ ] Security audit passed

---

## Implementation Priority

### Phase 1: Critical Security (Week 1)
1. API gateway with mTLS + signature validation
2. Nonce/timestamp validation
3. Rate limiting enforcement
4. Quota pre-check

### Phase 2: Hardening (Week 2)
1. Distributed rate limiting (Redis cluster)
2. Audit logging with tenant context
3. Secrets management integration
4. Network policy validation

### Phase 3: Operationalization (Week 3)
1. Monitoring dashboards
2. Alerting rules
3. Backup automation
4. CI/CD pipelines

---

## File Structure

```
/home/sdx/Projects/mirqab-cloud-relay/
├── services/
│   ├── api-gateway/           # NEW: Central security layer
│   │   ├── main.py
│   │   ├── auth.py            # mTLS + API key validation
│   │   ├── rate_limiter.py    # Distributed rate limiting
│   │   ├── quota.py           # Quota enforcement
│   │   ├── signature.py       # Request signing validation
│   │   └── middleware.py      # Security middleware
│   ├── http-c2/
│   ├── waf-tester/
│   └── payload-server/
├── kubernetes/
│   ├── base/
│   │   ├── api-gateway/       # NEW
│   │   └── ...
│   └── overlays/
├── terraform/
└── docs/
    ├── PRODUCTION_REQUIREMENTS.md  # This file
    └── MULTI_TENANT_ARCHITECTURE.md
```

---

## Deployment Instructions

### Local Testing

```bash
# Start services locally
cd /home/sdx/Projects/mirqab-cloud-relay
docker compose up -d redis api-gateway

# Verify health
curl http://localhost:8100/health
curl http://localhost:8100/ready

# Test authentication (will fail without valid credentials)
curl -H "X-Tenant-ID: test-tenant" http://localhost:8100/api/v1/quota
```

### Transfer to Cloud Relay VM

```bash
# Set up SSH key (one-time)
ssh-copy-id sdx@192.168.100.67

# Transfer api-gateway service
rsync -avz services/api-gateway/ sdx@192.168.100.67:~/mirqab-cloud-relay/services/api-gateway/

# Transfer updated docker-compose
rsync -avz docker-compose.yml sdx@192.168.100.67:~/mirqab-cloud-relay/

# SSH to VM and deploy
ssh sdx@192.168.100.67 "cd ~/mirqab-cloud-relay && docker compose up -d --build api-gateway"
```

### Production Deployment

Environment variables for production:

```bash
REDIS_URL=redis://redis-cluster:6379/0
REQUIRE_MTLS=true
REQUIRE_SIGNATURE=true
DEBUG=false
HTTP_C2_URL=http://http-c2:8080
WAF_TESTER_URL=http://waf-tester:8443
PAYLOAD_SERVER_URL=http://payload-server:8000
```

---

## Implementation Status

### Phase 1: Critical Security - COMPLETE
- [x] API gateway with mTLS + signature validation (`auth.py`)
- [x] Nonce/timestamp validation (`signature.py`)
- [x] Rate limiting enforcement (`rate_limiter.py`)
- [x] Quota pre-check (`quota.py`)

### Phase 2: Hardening - PARTIAL
- [x] Distributed rate limiting (Redis sorted sets)
- [x] Audit logging with tenant context
- [ ] Secrets management integration (HashiCorp Vault)
- [ ] Network policy validation (Kubernetes)

### Phase 3: Operationalization - PENDING
- [ ] Monitoring dashboards (Prometheus/Grafana)
- [ ] Alerting rules
- [ ] Backup automation
- [ ] CI/CD pipelines

---

## API Gateway Files

| File | Description |
|------|-------------|
| `main.py` | FastAPI application entry point |
| `auth.py` | mTLS + API key authentication |
| `signature.py` | HMAC-SHA256 signature validation |
| `rate_limiter.py` | Redis-based distributed rate limiting |
| `quota.py` | Quota enforcement (agents, tasks, features) |
| `middleware.py` | Security middleware combining all checks |
| `models.py` | Data models (Tenant, TierLimits, etc.) |
| `Dockerfile` | Container build |
| `requirements.txt` | Python dependencies |
