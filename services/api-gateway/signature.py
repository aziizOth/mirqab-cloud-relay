"""
Cloud Relay API Gateway - Request Signature Validation

Implements HMAC-SHA256 signature validation with nonce and timestamp
to prevent replay attacks and ensure request integrity.
"""
from __future__ import annotations

import hashlib
import hmac
import logging
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from redis.asyncio import Redis

logger = logging.getLogger("cloud-relay.signature")

# Configuration
REQUEST_TIMESTAMP_TOLERANCE = timedelta(minutes=5)
NONCE_EXPIRY_SECONDS = 600  # 10 minutes


class SignatureValidationError(Exception):
    """Raised when signature validation fails."""

    def __init__(self, message: str, code: str = "invalid_signature"):
        self.message = message
        self.code = code
        super().__init__(message)


class SignatureValidator:
    """
    Validates request signatures using HMAC-SHA256.

    Signature format:
        HMAC-SHA256(api_secret, f"{body}|{timestamp}|{nonce}")

    Security features:
        - Timestamp validation (reject requests older than 5 minutes)
        - Nonce validation (prevent replay attacks)
        - Constant-time comparison (prevent timing attacks)
    """

    def __init__(self, redis_client: Redis):
        self.redis = redis_client

    async def validate(
        self,
        body: bytes,
        timestamp: str,
        nonce: str,
        signature: str,
        api_secret: str,
        tenant_id: str,
    ) -> None:
        """
        Validate request signature.

        Args:
            body: Raw request body bytes
            timestamp: ISO8601 timestamp from X-Request-Timestamp header
            nonce: Unique request ID from X-Request-Nonce header
            signature: HMAC signature from X-Request-Signature header
            api_secret: Tenant's API secret for signature verification
            tenant_id: Tenant ID for nonce namespacing

        Raises:
            SignatureValidationError: If validation fails
        """
        # 1. Validate timestamp
        await self._validate_timestamp(timestamp)

        # 2. Validate nonce (not reused)
        await self._validate_nonce(nonce, tenant_id)

        # 3. Validate signature
        self._validate_signature(body, timestamp, nonce, signature, api_secret)

        logger.debug(
            "Signature validated",
            extra={
                "tenant_id": tenant_id,
                "nonce": nonce,
                "timestamp": timestamp,
            },
        )

    async def _validate_timestamp(self, timestamp: str) -> None:
        """Validate request timestamp is within acceptable window."""
        try:
            # Parse ISO8601 timestamp
            if timestamp.endswith("Z"):
                timestamp = timestamp[:-1] + "+00:00"
            request_time = datetime.fromisoformat(timestamp)

            # Ensure timezone aware
            if request_time.tzinfo is None:
                request_time = request_time.replace(tzinfo=timezone.utc)

            now = datetime.now(timezone.utc)
            age = abs((now - request_time).total_seconds())

            if age > REQUEST_TIMESTAMP_TOLERANCE.total_seconds():
                raise SignatureValidationError(
                    f"Request timestamp expired (age: {age:.0f}s, max: {REQUEST_TIMESTAMP_TOLERANCE.total_seconds():.0f}s)",
                    code="timestamp_expired",
                )

        except ValueError as e:
            raise SignatureValidationError(
                f"Invalid timestamp format: {e}",
                code="invalid_timestamp",
            )

    async def _validate_nonce(self, nonce: str, tenant_id: str) -> None:
        """
        Validate nonce has not been used before.
        Uses Redis to track nonces with automatic expiry.
        """
        if not nonce:
            raise SignatureValidationError(
                "Missing request nonce",
                code="missing_nonce",
            )

        # Check minimum nonce length (should be UUID)
        if len(nonce) < 32:
            raise SignatureValidationError(
                "Invalid nonce format (expected UUID)",
                code="invalid_nonce",
            )

        # Namespace nonce by tenant to prevent cross-tenant collisions
        nonce_key = f"nonce:{tenant_id}:{nonce}"

        # Try to set nonce with NX (only if not exists)
        was_set = await self.redis.set(
            nonce_key,
            "1",
            ex=NONCE_EXPIRY_SECONDS,
            nx=True,
        )

        if not was_set:
            raise SignatureValidationError(
                "Nonce already used (possible replay attack)",
                code="nonce_reused",
            )

    def _validate_signature(
        self,
        body: bytes,
        timestamp: str,
        nonce: str,
        signature: str,
        api_secret: str,
    ) -> None:
        """Validate HMAC-SHA256 signature."""
        if not signature:
            raise SignatureValidationError(
                "Missing request signature",
                code="missing_signature",
            )

        # Build payload: body|timestamp|nonce
        body_str = body.decode("utf-8") if body else ""
        payload = f"{body_str}|{timestamp}|{nonce}"

        # Compute expected signature
        expected = hmac.new(
            api_secret.encode("utf-8"),
            payload.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()

        # Constant-time comparison to prevent timing attacks
        if not hmac.compare_digest(signature.lower(), expected.lower()):
            raise SignatureValidationError(
                "Invalid signature",
                code="signature_mismatch",
            )


def generate_signature(
    body: str,
    timestamp: str,
    nonce: str,
    api_secret: str,
) -> str:
    """
    Generate HMAC-SHA256 signature for a request.
    Used by clients (Master Server) to sign requests.

    Args:
        body: Request body as string
        timestamp: ISO8601 timestamp
        nonce: Unique request ID (UUID)
        api_secret: Tenant's API secret

    Returns:
        Hex-encoded HMAC-SHA256 signature
    """
    payload = f"{body}|{timestamp}|{nonce}"
    return hmac.new(
        api_secret.encode("utf-8"),
        payload.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
