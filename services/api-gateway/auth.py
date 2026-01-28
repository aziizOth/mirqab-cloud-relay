"""
Cloud Relay API Gateway - Authentication & Authorization

Implements multi-layer authentication:
1. mTLS certificate validation (tenant identity from cert CN)
2. API key validation (X-API-Key header)
3. Request signature validation (HMAC-SHA256)
"""
from __future__ import annotations

import hashlib
import logging
import os
import re
from datetime import datetime
from typing import TYPE_CHECKING

from models import AuthResult, Tenant, TenantTier

if TYPE_CHECKING:
    from redis.asyncio import Redis

logger = logging.getLogger("cloud-relay.auth")

# In-memory tenant cache (would be database in production)
# This is a placeholder - real implementation would use PostgreSQL
_TENANT_CACHE: dict[str, Tenant] = {}


class AuthenticationError(Exception):
    """Raised when authentication fails."""

    def __init__(self, message: str, code: str = "authentication_failed"):
        self.message = message
        self.code = code
        super().__init__(message)


class AuthorizationError(Exception):
    """Raised when authorization fails."""

    def __init__(self, message: str, code: str = "authorization_failed"):
        self.message = message
        self.code = code
        super().__init__(message)


class Authenticator:
    """
    Multi-layer authenticator for Cloud Relay requests.

    Authentication flow:
    1. Extract tenant ID from mTLS client certificate CN
    2. Verify X-Tenant-ID header matches certificate
    3. Validate X-API-Key header against tenant config
    4. (Signature validation is done separately)

    Security features:
    - mTLS provides strong identity verification
    - API key adds application-level authentication
    - Tenant ID must match in both certificate and header
    """

    def __init__(self, redis_client: Redis):
        self.redis = redis_client

    async def authenticate(
        self,
        mtls_subject: str | None,
        tenant_id_header: str | None,
        api_key: str | None,
    ) -> AuthResult:
        """
        Authenticate a request.

        Args:
            mtls_subject: Client certificate subject (CN=tenant-xxx)
            tenant_id_header: X-Tenant-ID header value
            api_key: X-API-Key header value

        Returns:
            AuthResult with authentication status and tenant info

        Raises:
            AuthenticationError: If authentication fails
        """
        # 1. Validate mTLS certificate
        if not mtls_subject:
            raise AuthenticationError(
                "Missing client certificate",
                code="missing_certificate",
            )

        cert_tenant_id = self._extract_tenant_from_cert(mtls_subject)
        if not cert_tenant_id:
            raise AuthenticationError(
                "Invalid certificate subject (expected CN=tenant-xxx)",
                code="invalid_certificate",
            )

        # 2. Verify X-Tenant-ID header matches certificate
        if not tenant_id_header:
            raise AuthenticationError(
                "Missing X-Tenant-ID header",
                code="missing_tenant_header",
            )

        if tenant_id_header != cert_tenant_id:
            logger.warning(
                "Tenant ID mismatch",
                extra={
                    "cert_tenant": cert_tenant_id,
                    "header_tenant": tenant_id_header,
                },
            )
            raise AuthenticationError(
                "X-Tenant-ID header does not match certificate",
                code="tenant_mismatch",
            )

        # 3. Load tenant configuration
        tenant = await self._load_tenant(cert_tenant_id)
        if not tenant:
            raise AuthenticationError(
                f"Tenant not found: {cert_tenant_id}",
                code="tenant_not_found",
            )

        if not tenant.active:
            raise AuthenticationError(
                "Tenant account is suspended",
                code="tenant_suspended",
            )

        # 4. Validate API key
        if not api_key:
            raise AuthenticationError(
                "Missing X-API-Key header",
                code="missing_api_key",
            )

        if not self._validate_api_key(api_key, tenant.api_key):
            raise AuthenticationError(
                "Invalid API key",
                code="invalid_api_key",
            )

        logger.info(
            "Authentication successful",
            extra={
                "tenant_id": tenant.id,
                "tenant_name": tenant.name,
                "tier": tenant.tier.value,
            },
        )

        return AuthResult(authenticated=True, tenant=tenant)

    def _extract_tenant_from_cert(self, subject: str) -> str | None:
        """
        Extract tenant ID from certificate subject.

        Expected format: CN=tenant-xxx,O=Mirqab,...
        """
        # Match CN=tenant-xxx pattern
        match = re.search(r"CN=([^,]+)", subject)
        if not match:
            return None

        cn = match.group(1)

        # Validate tenant ID format
        if not cn.startswith("tenant-"):
            # Also accept direct tenant IDs for backwards compatibility
            if re.match(r"^[a-z0-9]+-[a-z0-9]+$", cn):
                return cn
            return None

        return cn.replace("tenant-", "")

    async def _load_tenant(self, tenant_id: str) -> Tenant | None:
        """
        Load tenant configuration from cache or database.

        In production, this would query PostgreSQL with caching in Redis.
        """
        # Check in-memory cache first
        if tenant_id in _TENANT_CACHE:
            return _TENANT_CACHE[tenant_id]

        # Check Redis cache
        cached = await self.redis.get(f"tenant:{tenant_id}")
        if cached:
            # Deserialize and return
            # In production: return Tenant.from_json(cached)
            pass

        # Query database (placeholder)
        # In production: tenant = db.query(Tenant).filter(id=tenant_id).first()

        return None

    def _validate_api_key(self, provided: str, expected: str) -> bool:
        """
        Constant-time API key comparison to prevent timing attacks.
        """
        # Hash both keys for comparison (in case stored key is hashed)
        provided_hash = hashlib.sha256(provided.encode()).hexdigest()
        expected_hash = hashlib.sha256(expected.encode()).hexdigest()

        # Constant-time comparison
        return self._constant_time_compare(provided_hash, expected_hash)

    @staticmethod
    def _constant_time_compare(a: str, b: str) -> bool:
        """Constant-time string comparison."""
        if len(a) != len(b):
            return False
        result = 0
        for x, y in zip(a, b):
            result |= ord(x) ^ ord(y)
        return result == 0


class Authorizer:
    """
    Authorization checker for tenant permissions.

    Checks:
    - Tenant tier allows the requested feature
    - Tenant is within quota limits
    - Source IP is in allowlist (if configured)
    """

    async def authorize(
        self,
        tenant: Tenant,
        feature: str,
        source_ip: str | None = None,
    ) -> None:
        """
        Authorize a request for a specific feature.

        Args:
            tenant: Authenticated tenant
            feature: Feature/endpoint being accessed (e.g., "waf", "c2_http")
            source_ip: Source IP address (optional)

        Raises:
            AuthorizationError: If authorization fails
        """
        # 1. Check feature access
        from models import TIER_LIMITS

        tier_limits = TIER_LIMITS.get(tenant.tier)
        if not tier_limits:
            raise AuthorizationError(
                f"Unknown tier: {tenant.tier}",
                code="invalid_tier",
            )

        if feature not in tier_limits.allowed_features:
            raise AuthorizationError(
                f"Feature '{feature}' not available in {tenant.tier.value} tier",
                code="feature_not_allowed",
            )

        # 2. Check IP allowlist (if configured)
        if tenant.allowed_ips and source_ip:
            if not self._ip_in_allowlist(source_ip, tenant.allowed_ips):
                logger.warning(
                    "IP not in allowlist",
                    extra={
                        "tenant_id": tenant.id,
                        "source_ip": source_ip,
                        "allowed_ips": tenant.allowed_ips,
                    },
                )
                raise AuthorizationError(
                    "Source IP not in allowlist",
                    code="ip_not_allowed",
                )

        logger.debug(
            "Authorization successful",
            extra={
                "tenant_id": tenant.id,
                "feature": feature,
            },
        )

    def _ip_in_allowlist(self, ip: str, allowlist: list[str]) -> bool:
        """Check if IP is in allowlist (supports CIDR notation)."""
        import ipaddress

        try:
            ip_addr = ipaddress.ip_address(ip)

            for allowed in allowlist:
                try:
                    if "/" in allowed:
                        # CIDR notation
                        network = ipaddress.ip_network(allowed, strict=False)
                        if ip_addr in network:
                            return True
                    else:
                        # Single IP
                        if ip_addr == ipaddress.ip_address(allowed):
                            return True
                except ValueError:
                    continue

            return False

        except ValueError:
            return False


# Tenant management functions (for testing/development)


def register_tenant(tenant: Tenant) -> None:
    """Register a tenant in the in-memory cache."""
    _TENANT_CACHE[tenant.id] = tenant
    logger.info(f"Registered tenant: {tenant.id}")


def get_tenant(tenant_id: str) -> Tenant | None:
    """Get a tenant from the in-memory cache."""
    return _TENANT_CACHE.get(tenant_id)


def create_test_tenant(
    tenant_id: str,
    tier: TenantTier = TenantTier.PROFESSIONAL,
    api_key: str | None = None,
    api_secret: str | None = None,
) -> Tenant:
    """Create a test tenant for development."""
    import secrets

    tenant = Tenant(
        id=tenant_id,
        name=f"Test Tenant {tenant_id}",
        tier=tier,
        api_key=api_key or secrets.token_urlsafe(32),
        api_secret=api_secret or secrets.token_urlsafe(32),
        active=True,
        created_at=datetime.utcnow(),
    )
    register_tenant(tenant)
    return tenant


def load_secret(env_var: str) -> str:
    """
    Load a secret from environment variable or Docker secrets file.

    Checks {env_var}_FILE first (Docker secrets pattern: /run/secrets/...),
    falls back to {env_var} environment variable.
    """
    file_path = os.getenv(f"{env_var}_FILE")
    if file_path:
        try:
            with open(file_path) as f:
                return f.read().strip()
        except OSError:
            pass
    return os.getenv(env_var, "")


# Test credentials — loaded from env vars (set in docker-compose.yml or .env)
# Defaults provided for backward compatibility in local dev
TEST_API_KEY = load_secret("TEST_API_KEY") or "cloud-relay-test-api-key-2026"
TEST_API_SECRET = load_secret("TEST_API_SECRET") or "cloud-relay-test-api-secret-2026"
