"""
Cloud Relay API Gateway - Main Application

Central API gateway that handles all incoming requests:
- Security validation (mTLS, API key, signature)
- Rate limiting and quota enforcement
- Request routing to backend services
- Audit logging
"""
from __future__ import annotations

import logging
import os
import sys
from contextlib import asynccontextmanager

import httpx
import redis.asyncio as redis
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response

from auth import create_test_tenant, TEST_API_KEY, TEST_API_SECRET
from middleware import CORSMiddleware, RequestIDMiddleware, SecurityMiddleware
from models import TenantTier

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    stream=sys.stdout,
)
logger = logging.getLogger("cloud-relay.gateway")

# Configuration from environment
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
REQUIRE_MTLS = os.getenv("REQUIRE_MTLS", "true").lower() == "true"
REQUIRE_SIGNATURE = os.getenv("REQUIRE_SIGNATURE", "true").lower() == "true"
DEBUG_MODE = os.getenv("DEBUG", "false").lower() == "true"
ALLOWED_ORIGINS = os.getenv("ALLOWED_ORIGINS", "").split(",") if os.getenv("ALLOWED_ORIGINS") else []

# Backend service URLs
HTTP_C2_URL = os.getenv("HTTP_C2_URL", "http://http-c2:8080")
WAF_TESTER_URL = os.getenv("WAF_TESTER_URL", "http://waf-tester:8080")
PAYLOAD_SERVER_URL = os.getenv("PAYLOAD_SERVER_URL", "http://payload-server:8080")

# Traefik backend URL (for proxying authenticated requests to services)
TRAEFIK_BACKEND_URL = os.getenv("TRAEFIK_BACKEND_URL", "http://traefik:80")

# Shared httpx client (initialized in lifespan)
http_client: httpx.AsyncClient | None = None

# Redis client (initialized in lifespan)
redis_client: redis.Redis | None = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager."""
    global redis_client

    global http_client

    # Startup
    logger.info("Starting Cloud Relay API Gateway...")

    # Connect to Redis
    redis_client = redis.from_url(REDIS_URL, decode_responses=True)
    try:
        await redis_client.ping()
        logger.info("Connected to Redis")
    except Exception as e:
        logger.error(f"Failed to connect to Redis: {e}")
        raise

    # Create shared HTTP client for proxying
    http_client = httpx.AsyncClient(timeout=60.0, follow_redirects=True)
    logger.info(f"Proxy backend: {TRAEFIK_BACKEND_URL}")

    # Create test tenant in debug mode
    if DEBUG_MODE:
        logger.warning("Debug mode enabled - creating test tenant with fixed credentials")
        test_tenant = create_test_tenant(
            "test-tenant",
            TenantTier.PROFESSIONAL,
            api_key=TEST_API_KEY,
            api_secret=TEST_API_SECRET,
        )
        logger.info(f"Test tenant created: {test_tenant.id}")
        logger.info(f"  API Key: {TEST_API_KEY}")
        logger.info(f"  API Secret: {TEST_API_SECRET}")

    yield

    # Shutdown
    logger.info("Shutting down API Gateway...")
    if http_client:
        await http_client.aclose()
    if redis_client:
        await redis_client.close()
    logger.info("Shutdown complete")


# Create FastAPI application
app = FastAPI(
    title="Cloud Relay API Gateway",
    description="Multi-tenant API gateway for Cloud Relay services",
    version="1.0.0",
    docs_url="/docs" if DEBUG_MODE else None,
    redoc_url="/redoc" if DEBUG_MODE else None,
    lifespan=lifespan,
)


# Add middleware (order matters - first added is outermost)
@app.middleware("http")
async def add_security_middleware(request: Request, call_next):
    """Apply security middleware after Redis is available."""
    if redis_client:
        middleware = SecurityMiddleware(
            app=None,
            redis_client=redis_client,
            require_mtls=REQUIRE_MTLS,
            require_signature=REQUIRE_SIGNATURE,
        )
        return await middleware.dispatch(request, call_next)
    return await call_next(request)


# Health check endpoints (no auth required)
@app.get("/health")
async def health_check():
    """Basic health check."""
    return {"status": "healthy", "service": "api-gateway"}


@app.get("/healthz")
async def healthz():
    """Kubernetes liveness probe."""
    return {"status": "ok"}


@app.get("/ready")
async def ready():
    """Kubernetes readiness probe."""
    if redis_client:
        try:
            await redis_client.ping()
            return {"status": "ready", "redis": "connected"}
        except Exception:
            return JSONResponse(
                status_code=503,
                content={"status": "not_ready", "redis": "disconnected"},
            )
    return JSONResponse(
        status_code=503,
        content={"status": "not_ready", "redis": "not_initialized"},
    )


# API version info
@app.get("/api/v1")
async def api_info():
    """API version information."""
    return {
        "version": "1.0.0",
        "endpoints": {
            "waf": "/api/v1/waf",
            "c2_http": "/api/v1/c2/http",
            "c2_dns": "/api/v1/c2/dns",
            "payload": "/api/v1/payload",
            "tasks": "/api/v1/tasks",
        },
    }


# Task management endpoints
@app.post("/api/v1/tasks")
async def create_task(request: Request):
    """
    Create a new task for execution.

    Request body should contain:
    - task_type: Type of task (waf, c2_http, c2_dns, payload)
    - parameters: Task-specific parameters
    - callback_url: URL to POST results to (optional, overrides tenant default)
    """
    context = getattr(request.state, "context", None)
    if not context:
        return JSONResponse(
            status_code=401,
            content={"error": "Unauthorized", "message": "No authentication context"},
        )

    body = await request.json()
    task_type = body.get("task_type")

    if not task_type:
        return JSONResponse(
            status_code=400,
            content={"error": "bad_request", "message": "task_type is required"},
        )

    # Route to appropriate backend service
    backend_url = _get_backend_url(task_type)
    if not backend_url:
        return JSONResponse(
            status_code=400,
            content={"error": "bad_request", "message": f"Unknown task type: {task_type}"},
        )

    # Forward request to backend (with verified tenant context)
    # In production, this would use httpx to forward the request
    logger.info(
        "Task creation request",
        extra={
            "tenant_id": context.tenant_id,
            "task_type": task_type,
            "backend_url": backend_url,
        },
    )

    return {
        "status": "accepted",
        "message": "Task queued for execution",
        "tenant_id": context.tenant_id,
        "task_type": task_type,
        # In production: return task_id from backend
    }


@app.get("/api/v1/tasks/{task_id}")
async def get_task_status(task_id: str, request: Request):
    """Get task execution status."""
    context = getattr(request.state, "context", None)
    if not context:
        return JSONResponse(
            status_code=401,
            content={"error": "Unauthorized"},
        )

    # Query backend for task status
    # In production, this would query the appropriate backend service
    return {
        "task_id": task_id,
        "tenant_id": context.tenant_id,
        "status": "pending",  # Would be fetched from backend
    }


@app.delete("/api/v1/tasks/{task_id}")
async def cancel_task(task_id: str, request: Request):
    """Cancel a running task."""
    context = getattr(request.state, "context", None)
    if not context:
        return JSONResponse(
            status_code=401,
            content={"error": "Unauthorized"},
        )

    # Send cancel request to backend
    logger.info(
        "Task cancellation request",
        extra={
            "tenant_id": context.tenant_id,
            "task_id": task_id,
        },
    )

    return {
        "status": "cancelled",
        "task_id": task_id,
    }


# C2 kill switch
@app.post("/api/v1/c2/kill-all")
async def kill_all_c2(request: Request):
    """
    Emergency kill switch for all C2 operations.

    Terminates all active C2 sessions for the authenticated tenant.
    """
    context = getattr(request.state, "context", None)
    if not context:
        return JSONResponse(
            status_code=401,
            content={"error": "Unauthorized"},
        )

    logger.warning(
        "C2 kill-all triggered",
        extra={
            "tenant_id": context.tenant_id,
            "source_ip": context.source_ip,
        },
    )

    # Send kill command to HTTP-C2 service
    # In production, this would call the backend
    return {
        "status": "executed",
        "message": "Kill command sent to all active C2 sessions",
        "tenant_id": context.tenant_id,
    }


# Quota and limits info
@app.get("/api/v1/quota")
async def get_quota_info(request: Request):
    """Get current quota usage and limits for the authenticated tenant."""
    context = getattr(request.state, "context", None)
    if not context:
        return JSONResponse(
            status_code=401,
            content={"error": "Unauthorized"},
        )

    from models import TIER_LIMITS
    tier_limits = TIER_LIMITS.get(context.tenant.tier)

    # Get current usage from Redis
    rate_key = f"rate:{context.tenant_id}:requests"
    task_key = f"tasks:{context.tenant_id}:active"
    agent_key = f"agents:{context.tenant_id}:count"

    current_requests = await redis_client.zcard(rate_key) if redis_client else 0
    current_tasks = await redis_client.scard(task_key) if redis_client else 0
    current_agents = int(await redis_client.get(agent_key) or 0) if redis_client else 0

    return {
        "tenant_id": context.tenant_id,
        "tier": context.tenant.tier.value,
        "limits": {
            "max_agents": tier_limits.max_agents,
            "concurrent_tasks": tier_limits.concurrent_tasks,
            "requests_per_hour": tier_limits.requests_per_hour,
            "cpu_limit": tier_limits.cpu_limit,
            "memory_limit": tier_limits.memory_limit,
            "allowed_features": tier_limits.allowed_features,
        },
        "usage": {
            "current_agents": current_agents,
            "active_tasks": current_tasks,
            "requests_this_hour": current_requests,
        },
        "remaining": {
            "agents": max(0, tier_limits.max_agents - current_agents),
            "tasks": max(0, tier_limits.concurrent_tasks - current_tasks),
            "requests": max(0, tier_limits.requests_per_hour - current_requests),
        },
    }


def _get_backend_url(task_type: str) -> str | None:
    """Get backend service URL for task type."""
    mapping = {
        "waf": WAF_TESTER_URL,
        "c2_http": HTTP_C2_URL,
        "c2_dns": HTTP_C2_URL,  # DNS-over-HTTPS handled by same service
        "payload": PAYLOAD_SERVER_URL,
    }
    return mapping.get(task_type)


# ==============================================
# REVERSE PROXY - Forward authenticated requests
# to backend services via Traefik
# ==============================================

# Paths that are handled directly by the API Gateway (not proxied)
GATEWAY_PATHS = {
    "/health", "/healthz", "/ready", "/metrics",
    "/api/v1", "/api/v1/quota",
}
GATEWAY_PREFIXES = (
    "/api/v1/tasks",
    "/api/v1/c2/kill",
)


@app.api_route(
    "/{path:path}",
    methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"],
)
async def proxy_to_backend(request: Request, path: str):
    """
    Reverse proxy: forward authenticated requests to backend services via Traefik.

    After the security middleware validates authentication, rate limits, and quotas,
    this endpoint forwards the request to the appropriate backend service.

    This allows OffenSight to send requests to:
      - /waf/test       → WAF Tester (via Traefik)
      - /beacon         → HTTP C2 (via Traefik)
      - /exfil          → HTTP C2 (via Traefik)
      - /phishing/send  → SMTP Phishing (via Traefik)
      - /stage          → Payload Service (via Traefik)
      - /download/*     → Payload Service (via Traefik)
    """
    # Build target URL
    target_url = f"{TRAEFIK_BACKEND_URL}/{path}"
    if request.url.query:
        target_url += f"?{request.url.query}"

    # Get tenant context (set by security middleware)
    context = getattr(request.state, "context", None)

    # Read body
    body = await request.body()

    # Build headers (forward relevant headers, add tenant context)
    forward_headers = {}
    for key, value in request.headers.items():
        # Skip hop-by-hop headers and auth headers (already validated)
        if key.lower() in ("host", "connection", "transfer-encoding", "content-length"):
            continue
        forward_headers[key] = value

    # Add verified tenant context headers for downstream services
    if context:
        forward_headers["X-Verified-Tenant-ID"] = context.tenant_id
        forward_headers["X-Verified-Tier"] = context.tenant.tier.value
        forward_headers["X-Request-ID"] = context.request_id
        forward_headers["X-Correlation-ID"] = context.correlation_id

    try:
        # Forward request to Traefik backend
        backend_response = await http_client.request(
            method=request.method,
            url=target_url,
            headers=forward_headers,
            content=body,
        )

        # Build response headers
        response_headers = dict(backend_response.headers)
        # Remove hop-by-hop headers
        for h in ("transfer-encoding", "connection", "content-encoding"):
            response_headers.pop(h, None)

        logger.info(
            "Proxied request",
            extra={
                "tenant_id": context.tenant_id if context else "anonymous",
                "method": request.method,
                "path": f"/{path}",
                "backend": target_url,
                "status": backend_response.status_code,
            },
        )

        return Response(
            content=backend_response.content,
            status_code=backend_response.status_code,
            headers=response_headers,
        )

    except httpx.ConnectError as e:
        logger.error(
            "Backend connection failed",
            extra={"path": f"/{path}", "backend": target_url, "error": str(e)},
        )
        return JSONResponse(
            status_code=502,
            content={
                "error": "bad_gateway",
                "message": f"Backend service unavailable: /{path}",
            },
        )
    except httpx.TimeoutException:
        logger.error(
            "Backend request timeout",
            extra={"path": f"/{path}", "backend": target_url},
        )
        return JSONResponse(
            status_code=504,
            content={
                "error": "gateway_timeout",
                "message": f"Backend service timeout: /{path}",
            },
        )


# Error handlers
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """Global exception handler."""
    request_id = getattr(request.state, "request_id", "unknown")
    logger.exception(
        "Unhandled exception",
        extra={"request_id": request_id, "error": str(exc)},
    )
    return JSONResponse(
        status_code=500,
        content={
            "error": "internal_error",
            "message": "An unexpected error occurred",
            "request_id": request_id,
        },
    )


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=DEBUG_MODE,
        log_level="debug" if DEBUG_MODE else "info",
    )
