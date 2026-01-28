"""
Cloud Relay API Gateway - Security Middleware

Combines all security checks into a unified middleware:
1. mTLS certificate validation
2. API key authentication
3. Request signature validation
4. Rate limiting
5. Quota enforcement
"""
from __future__ import annotations

import logging
import time
import uuid
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Callable

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from auth import AuthenticationError, AuthorizationError, Authenticator, Authorizer
from models import AuditEvent, RequestContext
from quota import QuotaEnforcer
from rate_limiter import RateLimiter
from signature import SignatureValidationError, SignatureValidator

if TYPE_CHECKING:
    from redis.asyncio import Redis

logger = logging.getLogger("cloud-relay.middleware")

# Endpoints that skip authentication (health checks, etc.)
PUBLIC_ENDPOINTS = {
    "/health",
    "/healthz",
    "/ready",
    "/metrics",
}

# Mapping of endpoint prefixes to feature names
ENDPOINT_FEATURES = {
    "/api/v1/waf": "waf",
    "/api/v1/c2/http": "c2_http",
    "/api/v1/c2/dns": "c2_dns",
    "/api/v1/payload": "payload",
    "/api/v1/phishing": "phishing",
}


class SecurityMiddleware(BaseHTTPMiddleware):
    """
    Unified security middleware for all API requests.

    Request flow:
    1. Check if public endpoint (skip auth)
    2. Extract and validate mTLS certificate
    3. Validate API key
    4. Validate request signature (nonce + timestamp)
    5. Check rate limits
    6. Check quotas
    7. Authorize feature access
    8. Forward request with verified context
    9. Log audit event
    """

    def __init__(
        self,
        app,
        redis_client: Redis,
        require_mtls: bool = True,
        require_signature: bool = True,
    ):
        super().__init__(app)
        self.redis = redis_client
        self.require_mtls = require_mtls
        self.require_signature = require_signature

        # Initialize security components
        self.authenticator = Authenticator(redis_client)
        self.authorizer = Authorizer()
        self.signature_validator = SignatureValidator(redis_client)
        self.rate_limiter = RateLimiter(redis_client)
        self.quota_enforcer = QuotaEnforcer(redis_client)

    async def dispatch(
        self,
        request: Request,
        call_next: Callable,
    ) -> Response:
        """Process request through security pipeline."""
        start_time = time.time()
        request_id = request.headers.get("X-Request-ID", str(uuid.uuid4()))
        correlation_id = request.headers.get("X-Correlation-ID", request_id)

        # Add request tracking
        request.state.request_id = request_id
        request.state.correlation_id = correlation_id

        # Check if public endpoint
        if self._is_public_endpoint(request.url.path):
            return await call_next(request)

        try:
            # 1. Authenticate request
            context = await self._authenticate_request(request)
            request.state.context = context

            # 2. Validate signature (if required)
            if self.require_signature:
                await self._validate_signature(request, context)

            # 3. Check rate limits
            rate_result = await self.rate_limiter.check_rate_limit(
                context.tenant_id,
                context.tenant.tier,
            )
            if not rate_result.allowed:
                return self._rate_limit_response(rate_result, request_id)

            context.rate_limit_remaining = rate_result.remaining

            # 4. Determine feature from endpoint
            feature = self._get_feature_for_endpoint(request.url.path)

            # 5. Check quotas
            if feature:
                quota_result = await self.quota_enforcer.check_quota(
                    context.tenant,
                    feature,
                )
                if not quota_result.allowed:
                    return self._quota_exceeded_response(quota_result, request_id)

            # 6. Authorize feature access
            if feature:
                await self.authorizer.authorize(
                    context.tenant,
                    feature,
                    context.source_ip,
                )

            # 7. Add verified headers for downstream services
            request.state.verified_tenant_id = context.tenant_id
            request.state.verified_tier = context.tenant.tier.value

            # 8. Forward request
            response = await call_next(request)

            # 9. Add rate limit headers
            rate_headers = await self.rate_limiter.get_rate_limit_headers(
                context.tenant_id,
                context.tenant.tier,
            )
            for header, value in rate_headers.items():
                response.headers[header] = value

            # 10. Log audit event
            await self._log_audit_event(
                request=request,
                context=context,
                response=response,
                duration_ms=int((time.time() - start_time) * 1000),
            )

            return response

        except AuthenticationError as e:
            logger.warning(
                "Authentication failed",
                extra={
                    "request_id": request_id,
                    "error": e.message,
                    "code": e.code,
                    "path": request.url.path,
                },
            )
            return JSONResponse(
                status_code=401,
                content={
                    "error": "authentication_failed",
                    "code": e.code,
                    "message": e.message,
                    "request_id": request_id,
                },
                headers={"WWW-Authenticate": "mTLS, API-Key"},
            )

        except AuthorizationError as e:
            logger.warning(
                "Authorization failed",
                extra={
                    "request_id": request_id,
                    "error": e.message,
                    "code": e.code,
                    "path": request.url.path,
                },
            )
            return JSONResponse(
                status_code=403,
                content={
                    "error": "authorization_failed",
                    "code": e.code,
                    "message": e.message,
                    "request_id": request_id,
                },
            )

        except SignatureValidationError as e:
            logger.warning(
                "Signature validation failed",
                extra={
                    "request_id": request_id,
                    "error": e.message,
                    "code": e.code,
                    "path": request.url.path,
                },
            )
            return JSONResponse(
                status_code=401,
                content={
                    "error": "signature_invalid",
                    "code": e.code,
                    "message": e.message,
                    "request_id": request_id,
                },
            )

        except Exception as e:
            logger.exception(
                "Unexpected error in security middleware",
                extra={"request_id": request_id, "error": str(e)},
            )
            return JSONResponse(
                status_code=500,
                content={
                    "error": "internal_error",
                    "message": "An unexpected error occurred",
                    "request_id": request_id,
                },
            )

    def _is_public_endpoint(self, path: str) -> bool:
        """Check if endpoint is public (no auth required)."""
        return path in PUBLIC_ENDPOINTS

    async def _authenticate_request(self, request: Request) -> RequestContext:
        """Authenticate request and build context."""
        # Extract mTLS subject from header (set by ingress/proxy)
        mtls_subject = request.headers.get("X-Client-Cert-Subject")

        # In development, allow override
        if not mtls_subject and not self.require_mtls:
            mtls_subject = f"CN=tenant-{request.headers.get('X-Tenant-ID', 'unknown')}"

        # Get headers
        tenant_id_header = request.headers.get("X-Tenant-ID")
        api_key = request.headers.get("X-API-Key")

        # Authenticate
        auth_result = await self.authenticator.authenticate(
            mtls_subject=mtls_subject,
            tenant_id_header=tenant_id_header,
            api_key=api_key,
        )

        if not auth_result.authenticated or not auth_result.tenant:
            raise AuthenticationError(
                auth_result.error or "Authentication failed",
                code="auth_failed",
            )

        # Build request context
        return RequestContext(
            tenant_id=auth_result.tenant.id,
            tenant=auth_result.tenant,
            request_id=request.state.request_id,
            correlation_id=request.state.correlation_id,
            timestamp=datetime.now(timezone.utc),
            nonce=request.headers.get("X-Request-Nonce", ""),
            source_ip=self._get_client_ip(request),
            user_agent=request.headers.get("User-Agent", "unknown"),
        )

    async def _validate_signature(
        self,
        request: Request,
        context: RequestContext,
    ) -> None:
        """Validate request signature."""
        body = await request.body()
        timestamp = request.headers.get("X-Request-Timestamp", "")
        nonce = request.headers.get("X-Request-Nonce", "")
        signature = request.headers.get("X-Request-Signature", "")

        await self.signature_validator.validate(
            body=body,
            timestamp=timestamp,
            nonce=nonce,
            signature=signature,
            api_secret=context.tenant.api_secret,
            tenant_id=context.tenant_id,
        )

    def _get_feature_for_endpoint(self, path: str) -> str | None:
        """Map endpoint path to feature name."""
        for prefix, feature in ENDPOINT_FEATURES.items():
            if path.startswith(prefix):
                return feature
        return None

    def _get_client_ip(self, request: Request) -> str:
        """Extract client IP from request."""
        # Check X-Forwarded-For first (set by proxy)
        forwarded = request.headers.get("X-Forwarded-For")
        if forwarded:
            # First IP is the original client
            return forwarded.split(",")[0].strip()

        # Check X-Real-IP
        real_ip = request.headers.get("X-Real-IP")
        if real_ip:
            return real_ip

        # Fall back to direct connection
        if request.client:
            return request.client.host

        return "unknown"

    def _rate_limit_response(self, rate_result, request_id: str) -> JSONResponse:
        """Build rate limit exceeded response."""
        return JSONResponse(
            status_code=429,
            content={
                "error": "rate_limit_exceeded",
                "message": "Request rate limit exceeded",
                "retry_after": rate_result.retry_after,
                "reset_at": rate_result.reset_at,
                "request_id": request_id,
            },
            headers={
                "Retry-After": str(rate_result.retry_after),
                "X-RateLimit-Remaining": "0",
                "X-RateLimit-Reset": str(int(rate_result.reset_at)),
            },
        )

    def _quota_exceeded_response(self, quota_result, request_id: str) -> JSONResponse:
        """Build quota exceeded response."""
        return JSONResponse(
            status_code=429,
            content={
                "error": "quota_exceeded",
                "message": quota_result.reason,
                "retry_after": quota_result.retry_after,
                "request_id": request_id,
            },
            headers={
                "Retry-After": str(quota_result.retry_after) if quota_result.retry_after else "60",
            },
        )

    async def _log_audit_event(
        self,
        request: Request,
        context: RequestContext,
        response: Response,
        duration_ms: int,
    ) -> None:
        """Log audit event for the request."""
        event = AuditEvent(
            timestamp=datetime.now(timezone.utc),
            event_type="api_request",
            tenant_id=context.tenant_id,
            request_id=context.request_id,
            correlation_id=context.correlation_id,
            source_ip=context.source_ip,
            user_agent=context.user_agent,
            endpoint=str(request.url.path),
            method=request.method,
            status_code=response.status_code,
            duration_ms=duration_ms,
            details={
                "tier": context.tenant.tier.value,
                "rate_limit_remaining": context.rate_limit_remaining,
            },
        )

        # Store audit event in Redis for async processing
        try:
            await self.redis.lpush(
                "audit:events",
                event.__dict__.__str__(),
            )
            # Trim to keep last 10000 events
            await self.redis.ltrim("audit:events", 0, 9999)
        except Exception as e:
            logger.error(
                "Failed to store audit event",
                extra={"error": str(e), "request_id": context.request_id},
            )

        # Also log for immediate visibility
        logger.info(
            "API request completed",
            extra={
                "tenant_id": context.tenant_id,
                "request_id": context.request_id,
                "method": request.method,
                "path": str(request.url.path),
                "status_code": response.status_code,
                "duration_ms": duration_ms,
            },
        )


class RequestIDMiddleware(BaseHTTPMiddleware):
    """
    Middleware to ensure all requests have a unique ID.
    """

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        request_id = request.headers.get("X-Request-ID", str(uuid.uuid4()))
        request.state.request_id = request_id

        response = await call_next(request)
        response.headers["X-Request-ID"] = request_id

        return response


class CORSMiddleware(BaseHTTPMiddleware):
    """
    CORS middleware for API gateway.
    Note: In production, CORS should be restricted to known Master Server origins.
    """

    def __init__(self, app, allowed_origins: list[str] | None = None):
        super().__init__(app)
        self.allowed_origins = allowed_origins or []

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        origin = request.headers.get("Origin")

        # Handle preflight
        if request.method == "OPTIONS":
            return self._preflight_response(origin)

        response = await call_next(request)

        # Add CORS headers
        if origin and (not self.allowed_origins or origin in self.allowed_origins):
            response.headers["Access-Control-Allow-Origin"] = origin
            response.headers["Access-Control-Allow-Credentials"] = "true"

        return response

    def _preflight_response(self, origin: str | None) -> Response:
        headers = {
            "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
            "Access-Control-Allow-Headers": (
                "Content-Type, X-API-Key, X-Tenant-ID, X-Request-Signature, "
                "X-Request-Timestamp, X-Request-Nonce, X-Correlation-ID"
            ),
            "Access-Control-Max-Age": "86400",
        }

        if origin and (not self.allowed_origins or origin in self.allowed_origins):
            headers["Access-Control-Allow-Origin"] = origin
            headers["Access-Control-Allow-Credentials"] = "true"

        return Response(status_code=204, headers=headers)
