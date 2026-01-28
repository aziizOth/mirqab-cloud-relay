"""
Cloud Relay API Gateway - Quota Enforcement

Enforces resource quotas before task execution:
- Agent count limits
- Concurrent task limits
- Feature access per tier
"""
from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from models import QuotaResult, Tenant, TenantTier, TIER_LIMITS

if TYPE_CHECKING:
    from redis.asyncio import Redis

logger = logging.getLogger("cloud-relay.quota")


class QuotaEnforcer:
    """
    Enforces resource quotas for tenants.

    Quota checks:
    - Agent count within tier limits
    - Concurrent tasks within tier limits
    - Feature access allowed for tier
    - Bandwidth/storage limits (future)
    """

    def __init__(self, redis_client: Redis):
        self.redis = redis_client

    async def check_quota(
        self,
        tenant: Tenant,
        task_type: str,
        resource_requirements: dict | None = None,
    ) -> QuotaResult:
        """
        Check if tenant is within all quotas for the requested operation.

        Args:
            tenant: Authenticated tenant
            task_type: Type of task (e.g., "waf", "c2_http", "payload")
            resource_requirements: Optional resource requirements dict

        Returns:
            QuotaResult with allowed status and reason if denied
        """
        tier_limits = TIER_LIMITS.get(tenant.tier)
        if not tier_limits:
            return QuotaResult(
                allowed=False,
                reason=f"Unknown tier: {tenant.tier.value}",
            )

        # 1. Check feature access
        if task_type not in tier_limits.allowed_features:
            logger.warning(
                "Feature not allowed for tier",
                extra={
                    "tenant_id": tenant.id,
                    "tier": tenant.tier.value,
                    "task_type": task_type,
                    "allowed_features": tier_limits.allowed_features,
                },
            )
            return QuotaResult(
                allowed=False,
                reason=f"Feature '{task_type}' not available in {tenant.tier.value} tier. "
                       f"Upgrade to access this feature.",
            )

        # 2. Check agent count
        agent_count_result = await self._check_agent_count(tenant, tier_limits.max_agents)
        if not agent_count_result.allowed:
            return agent_count_result

        # 3. Check concurrent tasks
        concurrent_result = await self._check_concurrent_tasks(
            tenant, tier_limits.concurrent_tasks
        )
        if not concurrent_result.allowed:
            return concurrent_result

        # 4. Check resource requirements (if specified)
        if resource_requirements:
            resource_result = await self._check_resource_requirements(
                tenant, tier_limits, resource_requirements
            )
            if not resource_result.allowed:
                return resource_result

        logger.debug(
            "Quota check passed",
            extra={
                "tenant_id": tenant.id,
                "tier": tenant.tier.value,
                "task_type": task_type,
            },
        )

        return QuotaResult(allowed=True)

    async def _check_agent_count(
        self,
        tenant: Tenant,
        max_agents: int,
    ) -> QuotaResult:
        """Check if tenant is within agent count limit."""
        key = f"agents:{tenant.id}:count"

        try:
            current = await self.redis.get(key)
            current_count = int(current) if current else 0

            if current_count >= max_agents:
                logger.warning(
                    "Agent limit exceeded",
                    extra={
                        "tenant_id": tenant.id,
                        "current": current_count,
                        "limit": max_agents,
                    },
                )
                return QuotaResult(
                    allowed=False,
                    reason=f"Agent limit exceeded ({current_count}/{max_agents}). "
                           f"Deregister unused agents or upgrade your tier.",
                )

            return QuotaResult(allowed=True)

        except Exception as e:
            logger.error(
                "Agent count check failed",
                extra={"tenant_id": tenant.id, "error": str(e)},
            )
            # Fail open for availability (could be configured to fail closed)
            return QuotaResult(allowed=True)

    async def _check_concurrent_tasks(
        self,
        tenant: Tenant,
        max_concurrent: int,
    ) -> QuotaResult:
        """Check if tenant is within concurrent task limit."""
        key = f"tasks:{tenant.id}:active"

        try:
            current = await self.redis.scard(key)

            if current >= max_concurrent:
                logger.warning(
                    "Concurrent task limit exceeded",
                    extra={
                        "tenant_id": tenant.id,
                        "current": current,
                        "limit": max_concurrent,
                    },
                )
                return QuotaResult(
                    allowed=False,
                    reason=f"Concurrent task limit exceeded ({current}/{max_concurrent}). "
                           f"Wait for running tasks to complete.",
                    retry_after=30,
                )

            return QuotaResult(allowed=True)

        except Exception as e:
            logger.error(
                "Concurrent task check failed",
                extra={"tenant_id": tenant.id, "error": str(e)},
            )
            return QuotaResult(allowed=True)

    async def _check_resource_requirements(
        self,
        tenant: Tenant,
        tier_limits,
        requirements: dict,
    ) -> QuotaResult:
        """Check if requested resources are within tier limits."""
        # Parse CPU limit (e.g., "500m" -> 0.5, "2" -> 2)
        requested_cpu = requirements.get("cpu")
        if requested_cpu:
            requested = self._parse_cpu(requested_cpu)
            limit = self._parse_cpu(tier_limits.cpu_limit)
            if requested > limit:
                return QuotaResult(
                    allowed=False,
                    reason=f"CPU request ({requested_cpu}) exceeds tier limit ({tier_limits.cpu_limit})",
                )

        # Parse memory limit (e.g., "512Mi" -> 512, "1Gi" -> 1024)
        requested_memory = requirements.get("memory")
        if requested_memory:
            requested = self._parse_memory(requested_memory)
            limit = self._parse_memory(tier_limits.memory_limit)
            if requested > limit:
                return QuotaResult(
                    allowed=False,
                    reason=f"Memory request ({requested_memory}) exceeds tier limit ({tier_limits.memory_limit})",
                )

        return QuotaResult(allowed=True)

    @staticmethod
    def _parse_cpu(cpu_str: str) -> float:
        """Parse Kubernetes CPU format to float cores."""
        if cpu_str.endswith("m"):
            return float(cpu_str[:-1]) / 1000
        return float(cpu_str)

    @staticmethod
    def _parse_memory(memory_str: str) -> int:
        """Parse Kubernetes memory format to MiB."""
        if memory_str.endswith("Gi"):
            return int(memory_str[:-2]) * 1024
        if memory_str.endswith("Mi"):
            return int(memory_str[:-2])
        if memory_str.endswith("Ki"):
            return int(memory_str[:-2]) // 1024
        return int(memory_str)


class AgentRegistry:
    """
    Manages agent registration for quota tracking.

    Tracks active agents per tenant for quota enforcement.
    """

    def __init__(self, redis_client: Redis):
        self.redis = redis_client

    async def register_agent(
        self,
        tenant_id: str,
        agent_id: str,
        ttl_seconds: int = 86400,  # 24 hours default
    ) -> bool:
        """
        Register an agent for the tenant.

        Args:
            tenant_id: Tenant identifier
            agent_id: Unique agent identifier
            ttl_seconds: Agent registration TTL

        Returns:
            True if registration successful
        """
        count_key = f"agents:{tenant_id}:count"
        set_key = f"agents:{tenant_id}:set"

        try:
            # Check if agent already registered
            if await self.redis.sismember(set_key, agent_id):
                logger.debug(
                    "Agent already registered",
                    extra={"tenant_id": tenant_id, "agent_id": agent_id},
                )
                return True

            # Add agent to set and increment count
            async with self.redis.pipeline(transaction=True) as pipe:
                pipe.sadd(set_key, agent_id)
                pipe.incr(count_key)
                pipe.expire(set_key, ttl_seconds)
                pipe.expire(count_key, ttl_seconds)
                await pipe.execute()

            logger.info(
                "Agent registered",
                extra={"tenant_id": tenant_id, "agent_id": agent_id},
            )
            return True

        except Exception as e:
            logger.error(
                "Agent registration failed",
                extra={"tenant_id": tenant_id, "agent_id": agent_id, "error": str(e)},
            )
            return False

    async def unregister_agent(
        self,
        tenant_id: str,
        agent_id: str,
    ) -> bool:
        """
        Unregister an agent from the tenant.

        Args:
            tenant_id: Tenant identifier
            agent_id: Agent identifier to remove

        Returns:
            True if unregistration successful
        """
        count_key = f"agents:{tenant_id}:count"
        set_key = f"agents:{tenant_id}:set"

        try:
            # Check if agent exists
            if not await self.redis.sismember(set_key, agent_id):
                logger.debug(
                    "Agent not registered",
                    extra={"tenant_id": tenant_id, "agent_id": agent_id},
                )
                return True

            # Remove agent from set and decrement count
            async with self.redis.pipeline(transaction=True) as pipe:
                pipe.srem(set_key, agent_id)
                pipe.decr(count_key)
                await pipe.execute()

            # Ensure count doesn't go negative
            current = await self.redis.get(count_key)
            if current and int(current) < 0:
                await self.redis.set(count_key, 0)

            logger.info(
                "Agent unregistered",
                extra={"tenant_id": tenant_id, "agent_id": agent_id},
            )
            return True

        except Exception as e:
            logger.error(
                "Agent unregistration failed",
                extra={"tenant_id": tenant_id, "agent_id": agent_id, "error": str(e)},
            )
            return False

    async def get_agent_count(self, tenant_id: str) -> int:
        """Get current agent count for tenant."""
        try:
            count = await self.redis.get(f"agents:{tenant_id}:count")
            return int(count) if count else 0
        except Exception:
            return 0

    async def list_agents(self, tenant_id: str) -> list[str]:
        """List all registered agent IDs for tenant."""
        try:
            agents = await self.redis.smembers(f"agents:{tenant_id}:set")
            return list(agents)
        except Exception:
            return []
