# Cloud Relay Multi-Tenant Architecture

## Overview

The Cloud Relay supports **multiple clients simultaneously** with full tenant isolation. Each client's Mirqab Master connects to the shared Cloud Relay infrastructure, and attacks execute in parallel with proper tenant tracking.

**Key Principle**: When Client A and Client B both trigger attacks at the same time:
- Both execute in **parallel** (no blocking)
- Results route back to the **correct client**
- Complete **data isolation** between tenants
- **Fair resource allocation** prevents noisy neighbor issues

---

## Existing Implementation

The `mirqab-cloud-relay` project already implements multi-tenancy:

| Component | Location | Multi-Tenant Feature |
|-----------|----------|---------------------|
| **TenantProvisioner** | `services/orchestrator/tenant_provisioner.py` | Per-tenant K8s namespaces, quotas, TLS certs |
| **HTTP C2 Service** | `services/http-c2/main.py` | `tenant_id` in BeaconRequest, ExfilData; tenant-partitioned GCS storage |
| **Subscription Tiers** | `docs/SUBSCRIPTION_TIERS.md` | TRIAL, STARTER, PROFESSIONAL, ENTERPRISE with different quotas |
| **Client Registration** | `docs/CLIENT_REGISTRATION_FLOW.md` | License activation → Tenant provisioning → Credentials |

### Tier-Based Quotas (from tenant_provisioner.py)

| Tier | Max Agents | Max Concurrent Executions | CPU Limit | Memory Limit |
|------|------------|---------------------------|-----------|--------------|
| TRIAL | 3 | 1 | 1 core | 1Gi |
| STARTER | 10 | 3 | 2 cores | 2Gi |
| PROFESSIONAL | 50 | 10 | 4 cores | 4Gi |
| ENTERPRISE | 200 | 50 | 8 cores | 8Gi |

---

## Multi-Tenant Requirements

1. **Parallel Execution**: Multiple clients can run attacks simultaneously
2. **Tenant Isolation**: Each client's data is isolated from others
3. **Result Routing**: Results return to the correct client's Master
4. **Resource Fairness**: No single tenant can monopolize resources
5. **Audit Trail**: All actions tagged with tenant ID
6. **Security**: Tenant data never leaks between clients

---

## Architecture

### Tenant Identification Flow

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                        MULTI-TENANT CLOUD RELAY                                  │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                  │
│   CLIENT A (Mirqab Master)              CLIENT B (Mirqab Master)                │
│   tenant_id: "client-a-uuid"            tenant_id: "client-b-uuid"              │
│         │                                      │                                 │
│         │ mTLS + tenant_id header              │ mTLS + tenant_id header        │
│         │                                      │                                 │
│         └──────────────┬───────────────────────┘                                │
│                        │                                                         │
│                        ▼                                                         │
│   ┌─────────────────────────────────────────────────────────────────────────┐   │
│   │                       API GATEWAY                                        │   │
│   │                                                                          │   │
│   │  1. Extract tenant_id from X-Tenant-ID header                           │   │
│   │  2. Validate tenant certificate (mTLS)                                  │   │
│   │  3. Route to service with tenant context                                │   │
│   │  4. Track metrics per tenant                                            │   │
│   └─────────────────────────────────────────────────────────────────────────┘   │
│                        │                                                         │
│         ┌──────────────┼──────────────┬──────────────┬──────────────┐           │
│         ▼              ▼              ▼              ▼              ▼           │
│   ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐        │
│   │ WAF      │  │ C2       │  │ Exfil    │  │ Phishing │  │ Payload  │        │
│   │ Tester   │  │ Listener │  │ Server   │  │ Server   │  │ Hosting  │        │
│   └──────────┘  └──────────┘  └──────────┘  └──────────┘  └──────────┘        │
│         │              │              │              │              │           │
│         └──────────────┴──────────────┴──────────────┴──────────────┘           │
│                                       │                                          │
│                                       ▼                                          │
│   ┌─────────────────────────────────────────────────────────────────────────┐   │
│   │                    TASK QUEUE (Redis)                                    │   │
│   │                                                                          │   │
│   │  Queue: tasks:client-a-uuid    Queue: tasks:client-b-uuid               │   │
│   │  ├── task-001 (waf-sqli)       ├── task-005 (c2-beacon)                 │   │
│   │  └── task-002 (waf-xss)        └── task-006 (exfil-dns)                 │   │
│   │                                                                          │   │
│   │  Results: results:client-a-uuid    Results: results:client-b-uuid       │   │
│   └─────────────────────────────────────────────────────────────────────────┘   │
│                                                                                  │
└─────────────────────────────────────────────────────────────────────────────────┘
```

### Task Envelope Structure

Every task includes tenant context:

```json
{
  "task_id": "task-001-uuid",
  "tenant_id": "client-a-uuid",
  "tenant_name": "Acme Corp",
  "callback_url": "https://acme-mirqab.example.com/api/v1/relay/callback",

  "execution_id": "exec-12345",
  "attack_id": "mirqab-waf-sqli-union",
  "attack_type": "INBOUND_EXTERNAL",

  "target": {
    "domain": "app.acme.com",
    "ip": null,
    "agent_id": null
  },

  "parameters": {
    "payload_type": "union",
    "encoding": "url"
  },

  "metadata": {
    "created_at": "2026-01-19T12:00:00Z",
    "priority": "normal",
    "timeout_seconds": 120
  }
}
```

### Result Envelope Structure

Results tagged for routing back to correct tenant:

```json
{
  "task_id": "task-001-uuid",
  "tenant_id": "client-a-uuid",
  "execution_id": "exec-12345",

  "status": "completed",
  "started_at": "2026-01-19T12:00:01Z",
  "completed_at": "2026-01-19T12:00:15Z",

  "result": {
    "blocked": true,
    "waf_response_code": 403,
    "waf_response_body": "Access Denied - SQL Injection Detected",
    "payloads_tested": 15,
    "payloads_blocked": 15
  },

  "evidence": {
    "request_log": "...",
    "response_headers": {...}
  }
}
```

---

## Database Schema (PostgreSQL)

### Tenants Table

```sql
CREATE TABLE tenants (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    api_key_hash VARCHAR(255) NOT NULL,
    certificate_thumbprint VARCHAR(64),
    callback_url VARCHAR(512) NOT NULL,

    -- Rate limiting
    max_concurrent_tasks INT DEFAULT 10,
    max_tasks_per_hour INT DEFAULT 100,

    -- Status
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),

    UNIQUE(name),
    UNIQUE(certificate_thumbprint)
);
```

### Tasks Table

```sql
CREATE TABLE tasks (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id),
    execution_id VARCHAR(64) NOT NULL,
    attack_id VARCHAR(128) NOT NULL,

    -- Task details
    task_type VARCHAR(64) NOT NULL,  -- waf, c2, exfil, phishing, payload
    target_domain VARCHAR(255),
    target_ip VARCHAR(45),
    parameters JSONB DEFAULT '{}',

    -- Status tracking
    status VARCHAR(32) DEFAULT 'pending',  -- pending, running, completed, failed, timeout
    priority VARCHAR(16) DEFAULT 'normal',  -- low, normal, high

    -- Timing
    created_at TIMESTAMPTZ DEFAULT NOW(),
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    timeout_at TIMESTAMPTZ,

    -- Results
    result JSONB,
    error_message TEXT,

    INDEX idx_tasks_tenant_status (tenant_id, status),
    INDEX idx_tasks_execution (execution_id)
);
```

### Audit Log Table

```sql
CREATE TABLE audit_log (
    id BIGSERIAL PRIMARY KEY,
    tenant_id UUID NOT NULL REFERENCES tenants(id),
    task_id UUID REFERENCES tasks(id),

    action VARCHAR(64) NOT NULL,  -- task_created, task_started, task_completed, etc.
    details JSONB DEFAULT '{}',
    source_ip VARCHAR(45),

    created_at TIMESTAMPTZ DEFAULT NOW(),

    INDEX idx_audit_tenant_time (tenant_id, created_at DESC)
);
```

---

## Redis Queue Structure

### Per-Tenant Task Queues

```
# Task queues (per tenant)
tasks:{tenant_id}:pending     # List of pending task IDs
tasks:{tenant_id}:running     # Set of currently running task IDs

# Task data (shared namespace, includes tenant_id in payload)
task:{task_id}                # Hash with task details

# Results (per tenant)
results:{tenant_id}           # List of completed task IDs
result:{task_id}              # Hash with result details

# Rate limiting (per tenant)
ratelimit:{tenant_id}:hour    # Counter for hourly rate limit
ratelimit:{tenant_id}:concurrent  # Gauge for concurrent tasks
```

### Worker Task Claiming

Workers claim tasks atomically:

```python
# Worker claims next task from any tenant (fair scheduling)
async def claim_next_task(worker_id: str) -> Task | None:
    # Round-robin through tenant queues
    for tenant_id in await get_active_tenants():
        # Check rate limits
        if await is_rate_limited(tenant_id):
            continue

        # Atomic claim
        task_id = await redis.rpoplpush(
            f"tasks:{tenant_id}:pending",
            f"tasks:{tenant_id}:running"
        )

        if task_id:
            await redis.sadd(f"tasks:{tenant_id}:running", task_id)
            await redis.hset(f"task:{task_id}", "worker_id", worker_id)
            await redis.incr(f"ratelimit:{tenant_id}:concurrent")
            return await get_task(task_id)

    return None
```

---

## API Gateway Multi-Tenant Enhancement

### Authentication Middleware

```python
from fastapi import Request, HTTPException
from fastapi.security import APIKeyHeader

api_key_header = APIKeyHeader(name="X-API-Key")
tenant_header = APIKeyHeader(name="X-Tenant-ID")

async def authenticate_tenant(request: Request) -> Tenant:
    """
    Authenticate tenant via:
    1. mTLS client certificate (preferred)
    2. API key + Tenant ID headers (fallback)
    """
    # Try mTLS first
    if request.state.ssl_client_cert:
        thumbprint = get_cert_thumbprint(request.state.ssl_client_cert)
        tenant = await get_tenant_by_cert(thumbprint)
        if tenant:
            return tenant

    # Fallback to API key
    api_key = request.headers.get("X-API-Key")
    tenant_id = request.headers.get("X-Tenant-ID")

    if not api_key or not tenant_id:
        raise HTTPException(401, "Missing authentication")

    tenant = await validate_api_key(tenant_id, api_key)
    if not tenant:
        raise HTTPException(401, "Invalid credentials")

    if not tenant.is_active:
        raise HTTPException(403, "Tenant suspended")

    return tenant
```

### Rate Limiting Middleware

```python
async def check_rate_limits(tenant: Tenant, request: Request):
    """
    Enforce per-tenant rate limits.
    """
    # Check concurrent tasks
    concurrent = await redis.get(f"ratelimit:{tenant.id}:concurrent") or 0
    if int(concurrent) >= tenant.max_concurrent_tasks:
        raise HTTPException(429, "Max concurrent tasks reached")

    # Check hourly limit
    hourly = await redis.get(f"ratelimit:{tenant.id}:hour") or 0
    if int(hourly) >= tenant.max_tasks_per_hour:
        raise HTTPException(429, "Hourly rate limit exceeded")
```

### Request Flow with Tenant Context

```python
@app.post("/api/v1/tasks")
async def create_task(
    task_request: TaskRequest,
    tenant: Tenant = Depends(authenticate_tenant)
):
    """
    Create a new attack task for the authenticated tenant.
    """
    # Rate limit check
    await check_rate_limits(tenant, request)

    # Create task with tenant context
    task = Task(
        id=uuid4(),
        tenant_id=tenant.id,
        execution_id=task_request.execution_id,
        attack_id=task_request.attack_id,
        task_type=task_request.task_type,
        target_domain=task_request.target.domain,
        parameters=task_request.parameters,
        callback_url=tenant.callback_url,
    )

    # Save to database
    await db.save(task)

    # Queue for execution
    await redis.lpush(f"tasks:{tenant.id}:pending", str(task.id))
    await redis.incr(f"ratelimit:{tenant.id}:hour")
    await redis.expire(f"ratelimit:{tenant.id}:hour", 3600)

    # Audit log
    await audit_log(tenant.id, task.id, "task_created", {
        "attack_id": task.attack_id,
        "target": task.target_domain
    })

    return TaskResponse(
        task_id=task.id,
        status="pending",
        estimated_start_seconds=await estimate_queue_wait(tenant.id)
    )
```

---

## Result Callback to Client Master

When a task completes, results are sent back to the originating client:

```python
async def send_result_callback(task: Task, result: TaskResult):
    """
    Send task result back to client's Mirqab Master.
    """
    callback_url = task.callback_url or await get_tenant_callback(task.tenant_id)

    payload = {
        "task_id": str(task.id),
        "execution_id": task.execution_id,
        "attack_id": task.attack_id,
        "status": result.status,
        "started_at": result.started_at.isoformat(),
        "completed_at": result.completed_at.isoformat(),
        "result": result.data,
        "evidence": result.evidence,
    }

    # Sign payload with tenant's shared secret
    signature = sign_payload(payload, tenant.shared_secret)

    headers = {
        "Content-Type": "application/json",
        "X-Relay-Signature": signature,
        "X-Task-ID": str(task.id),
    }

    async with httpx.AsyncClient() as client:
        try:
            response = await client.post(
                callback_url,
                json=payload,
                headers=headers,
                timeout=30.0
            )

            if response.status_code != 200:
                logger.warning("callback_failed",
                    tenant_id=task.tenant_id,
                    task_id=task.id,
                    status=response.status_code
                )
                # Queue for retry
                await queue_callback_retry(task.id, payload)

        except Exception as e:
            logger.error("callback_error",
                tenant_id=task.tenant_id,
                task_id=task.id,
                error=str(e)
            )
            await queue_callback_retry(task.id, payload)
```

---

## Client Master Integration

### Mirqab Master: Relay Callback Endpoint

```python
# app/api/v1/relay.py

@router.post("/relay/callback")
async def receive_relay_callback(
    request: Request,
    callback: RelayCallbackRequest,
    db: AsyncSession = Depends(get_db)
):
    """
    Receive attack results from Cloud Relay.
    """
    # Verify signature
    signature = request.headers.get("X-Relay-Signature")
    if not verify_relay_signature(callback.dict(), signature):
        raise HTTPException(401, "Invalid signature")

    # Find execution
    execution = await db.execute(
        select(Execution).where(Execution.id == callback.execution_id)
    )
    execution = execution.scalar_one_or_none()
    if not execution:
        raise HTTPException(404, "Execution not found")

    # Update execution step with relay results
    step = await get_execution_step(db, callback.execution_id, callback.attack_id)
    step.status = "completed" if callback.status == "completed" else "failed"
    step.command_output = json.dumps(callback.result)
    step.evidence = callback.evidence
    step.completed_at = datetime.fromisoformat(callback.completed_at)

    await db.commit()

    # Trigger evidence collection
    await collect_evidence_for_step(step)

    return {"status": "received", "task_id": callback.task_id}
```

### Mirqab Master: Submit Task to Relay

```python
# app/services/cloud_relay_service.py

class CloudRelayService:
    def __init__(self, relay_url: str, tenant_id: str, api_key: str):
        self.relay_url = relay_url
        self.tenant_id = tenant_id
        self.api_key = api_key

    async def submit_attack(
        self,
        execution_id: int,
        attack: AttackDefinition,
        target: str,
        parameters: dict
    ) -> str:
        """
        Submit an INBOUND_EXTERNAL or OUTBOUND_EXTERNAL attack to Cloud Relay.
        """
        payload = {
            "execution_id": str(execution_id),
            "attack_id": attack.attack_id,
            "task_type": self._get_task_type(attack),
            "target": {
                "domain": target if attack.execution_model_type == "inbound_external" else None,
            },
            "parameters": parameters,
        }

        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{self.relay_url}/api/v1/tasks",
                json=payload,
                headers={
                    "X-API-Key": self.api_key,
                    "X-Tenant-ID": self.tenant_id,
                }
            )
            response.raise_for_status()

            result = response.json()
            return result["task_id"]

    def _get_task_type(self, attack: AttackDefinition) -> str:
        """Map attack to relay task type."""
        if "waf" in attack.tags or "sqli" in attack.tags or "xss" in attack.tags:
            return "waf"
        elif "c2" in attack.tags or "beacon" in attack.tags:
            return "c2"
        elif "exfil" in attack.tags or "dns-tunnel" in attack.tags:
            return "exfil"
        elif "phishing" in attack.tags:
            return "phishing"
        else:
            return "payload"
```

---

## Metrics and Monitoring

### Per-Tenant Metrics

```python
# Prometheus metrics with tenant label
TASKS_CREATED = Counter(
    'cloudrelay_tasks_created_total',
    'Total tasks created',
    ['tenant_id', 'task_type']
)

TASKS_COMPLETED = Counter(
    'cloudrelay_tasks_completed_total',
    'Total tasks completed',
    ['tenant_id', 'task_type', 'status']
)

TASK_DURATION = Histogram(
    'cloudrelay_task_duration_seconds',
    'Task execution duration',
    ['tenant_id', 'task_type'],
    buckets=[1, 5, 10, 30, 60, 120, 300]
)

CONCURRENT_TASKS = Gauge(
    'cloudrelay_concurrent_tasks',
    'Currently running tasks',
    ['tenant_id']
)
```

### Grafana Dashboard Queries

```promql
# Tasks per tenant (last hour)
sum by (tenant_id) (increase(cloudrelay_tasks_created_total[1h]))

# Success rate per tenant
sum by (tenant_id) (rate(cloudrelay_tasks_completed_total{status="completed"}[5m]))
/
sum by (tenant_id) (rate(cloudrelay_tasks_completed_total[5m]))

# Average task duration per tenant
histogram_quantile(0.95,
  sum by (tenant_id, le) (rate(cloudrelay_task_duration_seconds_bucket[5m]))
)
```

---

## Security Considerations

### Tenant Isolation

1. **Data Isolation**: Each tenant's tasks and results stored with tenant_id FK
2. **Queue Isolation**: Separate Redis queues per tenant
3. **Network Isolation**: No cross-tenant communication possible
4. **Certificate Isolation**: Each tenant has unique mTLS certificate

### Preventing Cross-Tenant Access

```python
# All database queries MUST filter by tenant_id
async def get_task(task_id: str, tenant_id: str) -> Task:
    result = await db.execute(
        select(Task).where(
            Task.id == task_id,
            Task.tenant_id == tenant_id  # CRITICAL: Always filter
        )
    )
    return result.scalar_one_or_none()
```

### Audit Trail

Every action is logged with tenant context:

```python
async def audit_log(tenant_id: str, task_id: str, action: str, details: dict):
    await db.execute(
        insert(AuditLog).values(
            tenant_id=tenant_id,
            task_id=task_id,
            action=action,
            details=details,
            source_ip=get_client_ip(),
            created_at=datetime.utcnow()
        )
    )
```

---

## Deployment Configuration

### Environment Variables per Service

```yaml
# All services receive tenant context
environment:
  - MULTI_TENANT_ENABLED=true
  - TENANT_ISOLATION_MODE=strict  # strict | relaxed
  - MAX_TENANTS=100
  - DEFAULT_RATE_LIMIT_CONCURRENT=10
  - DEFAULT_RATE_LIMIT_HOURLY=100
```

### Kubernetes: Tenant Resource Quotas

```yaml
apiVersion: v1
kind: ResourceQuota
metadata:
  name: tenant-quota-{{ tenant_id }}
  namespace: cloud-relay
spec:
  hard:
    pods: "10"
    requests.cpu: "2"
    requests.memory: "4Gi"
    limits.cpu: "4"
    limits.memory: "8Gi"
```

---

## API Gateway Implementation Status

The API Gateway security layer has been **fully implemented** in `services/api-gateway/`:

### Implemented Components

| Component | File | Status |
|-----------|------|--------|
| **Authentication** | `auth.py` | COMPLETE |
| **Signature Validation** | `signature.py` | COMPLETE |
| **Rate Limiting** | `rate_limiter.py` | COMPLETE |
| **Quota Enforcement** | `quota.py` | COMPLETE |
| **Security Middleware** | `middleware.py` | COMPLETE |
| **FastAPI Application** | `main.py` | COMPLETE |

### Security Features Implemented

1. **Multi-Layer Authentication**
   - mTLS certificate validation (extract tenant ID from CN)
   - API key validation (constant-time comparison)
   - X-Tenant-ID header verification (must match certificate)

2. **Request Signature Validation**
   - HMAC-SHA256 signature: `HMAC(api_secret, body|timestamp|nonce)`
   - Timestamp validation (5-minute tolerance)
   - Nonce tracking in Redis (10-minute expiry, prevents replay attacks)

3. **Distributed Rate Limiting**
   - Sliding window algorithm using Redis sorted sets
   - Per-tenant rate limits based on tier
   - Concurrent task limiting using Redis sets
   - Graceful degradation if Redis unavailable

4. **Quota Enforcement**
   - Agent count limits per tier
   - Concurrent task limits per tier
   - Feature access control (WAF, C2, payload, phishing per tier)
   - Resource limits (CPU, memory)

5. **Audit Logging**
   - All requests logged with tenant context
   - Request ID and correlation ID tracking
   - Events stored in Redis for async processing

### API Gateway Endpoints

| Endpoint | Auth Required | Description |
|----------|---------------|-------------|
| `GET /health` | No | Health check |
| `GET /ready` | No | Readiness probe (checks Redis) |
| `GET /api/v1` | Yes | API version info |
| `POST /api/v1/tasks` | Yes | Create new task |
| `GET /api/v1/tasks/{id}` | Yes | Get task status |
| `DELETE /api/v1/tasks/{id}` | Yes | Cancel task |
| `POST /api/v1/c2/kill-all` | Yes | Emergency C2 kill switch |
| `GET /api/v1/quota` | Yes | Get quota usage |
| `/{path:path}` | Yes* | **Reverse proxy** — forwards to backend via Traefik |

> \*Security middleware validates auth; unauthenticated requests still proxied but without tenant context headers.

### Reverse Proxy (Added 2026-01-28)

The API Gateway now acts as a **reverse proxy** for all backend services. After authentication and rate limiting, requests are forwarded to Traefik which routes to the appropriate service:

```
OffenSight → API Gateway (port 8100) → Traefik (port 80) → Backend Service
                 │
                 ├── Auth validation
                 ├── Rate limiting
                 ├── Quota check
                 └── Forward with X-Verified-Tenant-ID header
```

**Proxied paths:**
- `/waf/*` → WAF Tester Service
- `/beacon`, `/exfil` → HTTP C2 Service
- `/phishing/*`, `/track/*`, `/landing/*` → SMTP Phishing Service
- `/download/*`, `/stage/*`, `/payloads/*` → Payload Service
- `/api/v1/payloads/*`, `/api/v1/sessions/*`, `/api/v1/c2/*` → C2 Gateway

**Headers added to proxied requests:**
- `X-Verified-Tenant-ID` — authenticated tenant identifier
- `X-Verified-Tier` — tenant subscription tier
- `X-Request-ID` — unique request identifier
- `X-Correlation-ID` — correlation ID for tracing

### Docker Deployment

```bash
# Local testing
docker compose up -d redis api-gateway
curl http://localhost:8100/health

# Production (with full security)
REQUIRE_MTLS=true REQUIRE_SIGNATURE=true docker compose up -d api-gateway
```

---

## Integration Testing Results (2026-01-28)

End-to-end testing verified OffenSight executing attack scenarios through the API Gateway:

### Test Environment

| Component | Host | Port |
|-----------|------|------|
| OffenSight Master | localhost | 8000 |
| API Gateway | 192.168.100.67 | 8100 |
| Traefik | 192.168.100.67 | 8180 |
| DVWA (target) | 192.168.100.67 | 8180/dvwa |

### Execution Results

| Execution | Scenario | Type | Steps | Result |
|-----------|----------|------|-------|--------|
| **#219** | Cloud Relay Outbound Attacks (Scenario 127) | `OUTBOUND_EXTERNAL` | **19/19 SUCCESS** | All C2 beacon, exfil, DNS tunnel steps executed |
| **#221** | Cloud Relay Inbound WAF Attacks (Scenario 128) | `INBOUND_EXTERNAL` | **32/32 SUCCESS** | SQLi, XSS, Command Injection, Path Traversal tests executed |

### Attack Categories Tested (Execution #221)

| Category | MITRE Technique | Steps | Status |
|----------|----------------|-------|--------|
| SQL Injection | T1190 | 8 | All executed (BLOCKED by target) |
| Cross-Site Scripting | T1189 | 8 | All executed (BLOCKED by target) |
| OS Command Injection | T1059 | 8 | All executed (BLOCKED by target) |
| Path Traversal | T1083 | 8 | All executed (BLOCKED by target) |

> **Note:** "BLOCKED" results are expected — the attacks reached the target (DVWA) through the API Gateway proxy but the DVWA session was not fully initialized. The important validation is that all 32 requests were successfully proxied through the API Gateway → Traefik → WAF Tester chain.

---

## Summary

| Feature | Implementation | Status |
|---------|----------------|--------|
| **Tenant Identification** | X-Tenant-ID header + mTLS certificate | IMPLEMENTED |
| **API Key Authentication** | X-API-Key header validation | IMPLEMENTED |
| **Request Signing** | HMAC-SHA256 with nonce/timestamp | IMPLEMENTED |
| **Rate Limiting** | Redis sliding window per tenant | IMPLEMENTED |
| **Quota Enforcement** | Tier-based limits | IMPLEMENTED |
| **Reverse Proxy** | httpx forwarding to Traefik with tenant headers | IMPLEMENTED |
| **Task Isolation** | Per-tenant Redis queues + DB foreign keys | IMPLEMENTED |
| **Parallel Execution** | Workers claim from round-robin tenant queues | IMPLEMENTED |
| **Result Routing** | Callback URL per tenant + signed payloads | IMPLEMENTED |
| **Audit Trail** | All actions logged with tenant_id | IMPLEMENTED |
| **Integration Testing** | OffenSight → Gateway → Traefik → Services | VERIFIED |
| **Metrics** | Prometheus metrics with tenant label | PARTIAL |
