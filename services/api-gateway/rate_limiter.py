"""
Cloud Relay API Gateway - Distributed Rate Limiting

Implements sliding window rate limiting using Redis for distributed
operation across multiple API gateway instances.
"""
from __future__ import annotations

import logging
import time
from typing import TYPE_CHECKING
from uuid import uuid4

from models import RateLimitResult, TenantTier, TIER_LIMITS

if TYPE_CHECKING:
    from redis.asyncio import Redis

logger = logging.getLogger("cloud-relay.rate_limiter")

# Rate limit window
RATE_LIMIT_WINDOW_SECONDS = 3600  # 1 hour


class RateLimiter:
    """
    Distributed rate limiter using Redis sorted sets.

    Implements sliding window algorithm:
    - Each request is stored with timestamp as score
    - Old entries (outside window) are automatically removed
    - Count of entries determines if limit is exceeded

    Features:
    - Distributed across multiple instances
    - Per-tenant rate limiting
    - Concurrent task limiting
    - Graceful degradation if Redis unavailable
    """

    def __init__(self, redis_client: Redis):
        self.redis = redis_client

    async def check_rate_limit(
        self,
        tenant_id: str,
        tier: TenantTier,
    ) -> RateLimitResult:
        """
        Check if request is within rate limits.

        Args:
            tenant_id: Tenant identifier
            tier: Tenant tier for limit lookup

        Returns:
            RateLimitResult with allowed status and remaining quota
        """
        now = time.time()
        window_start = now - RATE_LIMIT_WINDOW_SECONDS

        key = f"rate:{tenant_id}:requests"
        limit = TIER_LIMITS[tier].requests_per_hour

        try:
            # Pipeline for atomic operations
            async with self.redis.pipeline(transaction=True) as pipe:
                # Remove old entries outside the window
                pipe.zremrangebyscore(key, 0, window_start)
                # Count current entries
                pipe.zcard(key)
                # Execute pipeline
                results = await pipe.execute()

            current_count = results[1]

            if current_count >= limit:
                # Calculate when the oldest request expires
                oldest = await self.redis.zrange(key, 0, 0, withscores=True)
                reset_at = oldest[0][1] + RATE_LIMIT_WINDOW_SECONDS if oldest else now + RATE_LIMIT_WINDOW_SECONDS

                logger.warning(
                    "Rate limit exceeded",
                    extra={
                        "tenant_id": tenant_id,
                        "tier": tier.value,
                        "current": current_count,
                        "limit": limit,
                    },
                )

                return RateLimitResult(
                    allowed=False,
                    remaining=0,
                    reset_at=reset_at,
                    retry_after=int(reset_at - now),
                )

            # Add current request
            request_id = str(uuid4())
            await self.redis.zadd(key, {request_id: now})
            await self.redis.expire(key, RATE_LIMIT_WINDOW_SECONDS + 60)

            remaining = limit - current_count - 1

            logger.debug(
                "Rate limit check passed",
                extra={
                    "tenant_id": tenant_id,
                    "tier": tier.value,
                    "remaining": remaining,
                    "limit": limit,
                },
            )

            return RateLimitResult(
                allowed=True,
                remaining=remaining,
                reset_at=now + RATE_LIMIT_WINDOW_SECONDS,
            )

        except Exception as e:
            # Graceful degradation - allow request if Redis fails
            logger.error(
                "Rate limiter error, allowing request",
                extra={"tenant_id": tenant_id, "error": str(e)},
            )
            return RateLimitResult(allowed=True, remaining=-1)

    async def check_concurrent_tasks(
        self,
        tenant_id: str,
        tier: TenantTier,
    ) -> RateLimitResult:
        """
        Check if tenant can start a new concurrent task.

        Args:
            tenant_id: Tenant identifier
            tier: Tenant tier for limit lookup

        Returns:
            RateLimitResult with allowed status
        """
        key = f"tasks:{tenant_id}:active"
        limit = TIER_LIMITS[tier].concurrent_tasks

        try:
            current = await self.redis.scard(key)

            if current >= limit:
                logger.warning(
                    "Concurrent task limit exceeded",
                    extra={
                        "tenant_id": tenant_id,
                        "tier": tier.value,
                        "current": current,
                        "limit": limit,
                    },
                )
                return RateLimitResult(
                    allowed=False,
                    remaining=0,
                    retry_after=30,  # Suggest retry in 30 seconds
                )

            return RateLimitResult(
                allowed=True,
                remaining=limit - current,
            )

        except Exception as e:
            logger.error(
                "Concurrent task check error, allowing request",
                extra={"tenant_id": tenant_id, "error": str(e)},
            )
            return RateLimitResult(allowed=True, remaining=-1)

    async def register_task(
        self,
        tenant_id: str,
        task_id: str,
        ttl_seconds: int = 3600,
    ) -> None:
        """
        Register an active task for concurrent task limiting.

        Args:
            tenant_id: Tenant identifier
            task_id: Unique task identifier
            ttl_seconds: Task TTL (auto-cleanup if not explicitly removed)
        """
        key = f"tasks:{tenant_id}:active"
        try:
            await self.redis.sadd(key, task_id)
            await self.redis.expire(key, ttl_seconds)
            logger.debug(
                "Task registered",
                extra={"tenant_id": tenant_id, "task_id": task_id},
            )
        except Exception as e:
            logger.error(
                "Failed to register task",
                extra={"tenant_id": tenant_id, "task_id": task_id, "error": str(e)},
            )

    async def unregister_task(
        self,
        tenant_id: str,
        task_id: str,
    ) -> None:
        """
        Unregister a completed task.

        Args:
            tenant_id: Tenant identifier
            task_id: Task identifier to remove
        """
        key = f"tasks:{tenant_id}:active"
        try:
            await self.redis.srem(key, task_id)
            logger.debug(
                "Task unregistered",
                extra={"tenant_id": tenant_id, "task_id": task_id},
            )
        except Exception as e:
            logger.error(
                "Failed to unregister task",
                extra={"tenant_id": tenant_id, "task_id": task_id, "error": str(e)},
            )

    async def get_rate_limit_headers(
        self,
        tenant_id: str,
        tier: TenantTier,
    ) -> dict[str, str]:
        """
        Get rate limit headers for response.

        Returns headers per RFC 6585 / draft-ietf-httpapi-ratelimit-headers.
        """
        result = await self.check_rate_limit(tenant_id, tier)
        limit = TIER_LIMITS[tier].requests_per_hour

        return {
            "X-RateLimit-Limit": str(limit),
            "X-RateLimit-Remaining": str(max(0, result.remaining)),
            "X-RateLimit-Reset": str(int(result.reset_at)),
        }
