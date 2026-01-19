# Mirqab Cloud Relay - Network Actor Agent
"""
Main Network Actor agent that manages service exposure for testing.

This agent:
1. Connects to OffenSight Master for task polling
2. Exposes services on demand (SMB, RDP, SSH, HTTP)
3. Enforces source IP restrictions via firewall
4. Logs all access attempts
5. Auto-closes services after timeout
6. Reports results back to Master
"""

import asyncio
import logging
import os
import signal
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional
from pathlib import Path
import json

from .service_control import ServiceController, ServiceType, ServiceState, ServiceSession
from .firewall import FirewallManager, FirewallBackend
from .access_logger import AccessLogger, SessionStats

logger = logging.getLogger(__name__)


@dataclass
class NetworkActorConfig:
    """Configuration for Network Actor agent."""
    # Master connection
    master_url: str
    tenant_id: str
    api_key: str

    # Agent identity
    agent_id: str
    agent_name: Optional[str] = None

    # Service configuration
    default_timeout_seconds: int = 300
    max_timeout_seconds: int = 3600
    allowed_services: list[ServiceType] = field(
        default_factory=lambda: [
            ServiceType.SMB,
            ServiceType.RDP,
            ServiceType.SSH,
            ServiceType.HTTP,
        ]
    )

    # Firewall
    firewall_backend: Optional[FirewallBackend] = None

    # Logging
    log_dir: Path = Path("/var/log/mirqab-network-actor")

    # Polling
    poll_interval_seconds: float = 5.0

    @classmethod
    def from_env(cls) -> "NetworkActorConfig":
        """Create config from environment variables."""
        return cls(
            master_url=os.environ.get("MASTER_URL", "https://api.offensight.local:8000"),
            tenant_id=os.environ.get("TENANT_ID", ""),
            api_key=os.environ.get("API_KEY", ""),
            agent_id=os.environ.get("AGENT_ID", ""),
            agent_name=os.environ.get("AGENT_NAME"),
            default_timeout_seconds=int(os.environ.get("DEFAULT_TIMEOUT", "300")),
            max_timeout_seconds=int(os.environ.get("MAX_TIMEOUT", "3600")),
            log_dir=Path(os.environ.get("LOG_DIR", "/var/log/mirqab-network-actor")),
            poll_interval_seconds=float(os.environ.get("POLL_INTERVAL", "5.0")),
        )


@dataclass
class ServiceTask:
    """Task to open/close a service."""
    task_id: str
    execution_id: str
    action: str  # "open" or "close"
    service_type: ServiceType
    allowed_source_ip: str
    timeout_seconds: Optional[int] = None
    parameters: dict = field(default_factory=dict)


class NetworkActorAgent:
    """
    Network Actor agent for controlled service exposure.

    Lifecycle:
    1. IDLE - Agent running, no services exposed
    2. OPENING - Firewall rule added, service starting
    3. ACTIVE - Service running, accepting connections from source IP
    4. CLOSING - Service stopping, firewall rule removed
    5. REPORTING - Sending results to Master
    """

    def __init__(self, config: NetworkActorConfig):
        self.config = config

        # Initialize components
        self.firewall = FirewallManager(backend=config.firewall_backend)
        self.access_logger = AccessLogger(
            log_dir=config.log_dir,
            report_callback=self._report_to_master,
        )
        self.service_controller = ServiceController(
            firewall_manager=self.firewall,
            access_logger=self.access_logger,
            default_timeout_seconds=config.default_timeout_seconds,
            max_timeout_seconds=config.max_timeout_seconds,
        )

        # State
        self._running = False
        self._poll_task: Optional[asyncio.Task] = None
        self._http_client = None  # Will be httpx.AsyncClient

    async def start(self) -> None:
        """Start the Network Actor agent."""
        if self._running:
            return

        logger.info(f"Starting Network Actor agent: {self.config.agent_id}")

        # Initialize firewall
        await self.firewall.initialize()

        # Start access logger
        await self.access_logger.start()

        # Start polling for tasks
        self._running = True
        self._poll_task = asyncio.create_task(self._poll_loop())

        # Register with Master
        await self._register()

        logger.info("Network Actor agent started")

    async def stop(self) -> None:
        """Stop the Network Actor agent gracefully."""
        if not self._running:
            return

        logger.info("Stopping Network Actor agent...")
        self._running = False

        # Cancel poll task
        if self._poll_task:
            self._poll_task.cancel()
            try:
                await self._poll_task
            except asyncio.CancelledError:
                pass

        # Stop all active services
        await self.service_controller.stop_all()

        # Cleanup firewall rules
        await self.firewall.cleanup_all_rules()

        # Stop access logger
        await self.access_logger.stop()

        # Close HTTP client
        if self._http_client:
            await self._http_client.aclose()

        logger.info("Network Actor agent stopped")

    async def _register(self) -> None:
        """Register with Master server."""
        try:
            # Import httpx here to avoid circular imports
            import httpx

            if not self._http_client:
                self._http_client = httpx.AsyncClient(
                    base_url=self.config.master_url,
                    headers={
                        "X-Tenant-ID": self.config.tenant_id,
                        "X-API-Key": self.config.api_key,
                        "Content-Type": "application/json",
                    },
                    verify=False,  # For local testing
                    timeout=30.0,
                )

            response = await self._http_client.post(
                "/api/v1/agents/register",
                json={
                    "agent_id": self.config.agent_id,
                    "agent_name": self.config.agent_name or self.config.agent_id,
                    "agent_type": "network_actor",
                    "capabilities": [s.value for s in self.config.allowed_services],
                    "status": "online",
                },
            )
            response.raise_for_status()
            logger.info(f"Registered with Master: {self.config.agent_id}")

        except Exception as e:
            logger.error(f"Failed to register with Master: {e}")

    async def _poll_loop(self) -> None:
        """Poll Master for tasks."""
        import httpx

        while self._running:
            try:
                if not self._http_client:
                    self._http_client = httpx.AsyncClient(
                        base_url=self.config.master_url,
                        headers={
                            "X-Tenant-ID": self.config.tenant_id,
                            "X-API-Key": self.config.api_key,
                            "Content-Type": "application/json",
                        },
                        verify=False,
                        timeout=30.0,
                    )

                # Poll for network actor tasks
                response = await self._http_client.get(
                    "/api/v1/agents/poll",
                    params={
                        "agent_id": self.config.agent_id,
                        "agent_type": "network_actor",
                    },
                )

                if response.status_code == 200:
                    data = response.json()
                    tasks = data.get("tasks", [])
                    for task_data in tasks:
                        await self._handle_task(task_data)

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Poll error: {e}")

            await asyncio.sleep(self.config.poll_interval_seconds)

    async def _handle_task(self, task_data: dict) -> None:
        """Handle a service task from Master."""
        try:
            task = ServiceTask(
                task_id=task_data["task_id"],
                execution_id=task_data.get("execution_id", ""),
                action=task_data["action"],
                service_type=ServiceType(task_data["service_type"]),
                allowed_source_ip=task_data["allowed_source_ip"],
                timeout_seconds=task_data.get("timeout_seconds"),
                parameters=task_data.get("parameters", {}),
            )

            if task.service_type not in self.config.allowed_services:
                logger.warning(f"Service type not allowed: {task.service_type}")
                await self._report_task_result(task, success=False, error="Service type not allowed")
                return

            if task.action == "open":
                await self._handle_open_service(task)
            elif task.action == "close":
                await self._handle_close_service(task)
            else:
                logger.warning(f"Unknown action: {task.action}")

        except Exception as e:
            logger.error(f"Failed to handle task: {e}")
            await self._report_task_result(
                task_data.get("task_id", "unknown"),
                success=False,
                error=str(e),
            )

    async def _handle_open_service(self, task: ServiceTask) -> None:
        """Handle open service request."""
        logger.info(f"Opening {task.service_type.value} for {task.allowed_source_ip}")

        try:
            session = await self.service_controller.start_service(
                session_id=task.task_id,
                service_type=task.service_type,
                allowed_source_ip=task.allowed_source_ip,
                timeout_seconds=task.timeout_seconds,
                task_id=task.task_id,
                execution_id=task.execution_id,
            )

            await self._report_task_result(
                task,
                success=True,
                message=f"Service {task.service_type.value} opened",
                data={
                    "session_id": session.session_id,
                    "state": session.state.value,
                    "timeout_at": session.timeout_at.isoformat() if session.timeout_at else None,
                },
            )

        except Exception as e:
            logger.error(f"Failed to open service: {e}")
            await self._report_task_result(task, success=False, error=str(e))

    async def _handle_close_service(self, task: ServiceTask) -> None:
        """Handle close service request."""
        logger.info(f"Closing service for task {task.task_id}")

        try:
            session = await self.service_controller.stop_service(
                session_id=task.task_id,
                reason="manual_close",
            )

            # Get session stats
            stats = self.access_logger.get_session_stats(task.task_id)

            await self._report_task_result(
                task,
                success=True,
                message="Service closed",
                data={
                    "session_id": session.session_id,
                    "state": session.state.value,
                    "stats": stats.to_dict() if stats else None,
                },
            )

        except Exception as e:
            logger.error(f"Failed to close service: {e}")
            await self._report_task_result(task, success=False, error=str(e))

    async def _report_task_result(
        self,
        task: ServiceTask | str,
        success: bool,
        message: Optional[str] = None,
        error: Optional[str] = None,
        data: Optional[dict] = None,
    ) -> None:
        """Report task result to Master."""
        try:
            task_id = task.task_id if isinstance(task, ServiceTask) else task
            execution_id = task.execution_id if isinstance(task, ServiceTask) else ""

            if not self._http_client:
                return

            response = await self._http_client.post(
                f"/api/v1/agents/tasks/{task_id}/result",
                json={
                    "task_id": task_id,
                    "execution_id": execution_id,
                    "success": success,
                    "message": message,
                    "error": error,
                    "data": data,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                },
            )
            response.raise_for_status()

        except Exception as e:
            logger.error(f"Failed to report task result: {e}")

    async def _report_to_master(self, report: dict) -> None:
        """Callback to report session data to Master."""
        try:
            if not self._http_client:
                return

            response = await self._http_client.post(
                "/api/v1/agents/reports",
                json=report,
            )
            response.raise_for_status()

        except Exception as e:
            logger.error(f"Failed to send report to Master: {e}")

    # ==========================================================================
    # Direct API for local testing
    # ==========================================================================

    async def open_service(
        self,
        service_type: ServiceType,
        allowed_source_ip: str,
        timeout_seconds: Optional[int] = None,
    ) -> ServiceSession:
        """Open a service directly (for testing)."""
        import uuid
        session_id = str(uuid.uuid4())

        return await self.service_controller.start_service(
            session_id=session_id,
            service_type=service_type,
            allowed_source_ip=allowed_source_ip,
            timeout_seconds=timeout_seconds,
        )

    async def close_service(self, session_id: str) -> ServiceSession:
        """Close a service directly (for testing)."""
        return await self.service_controller.stop_service(session_id)

    def get_active_sessions(self) -> list[ServiceSession]:
        """Get all active service sessions."""
        return self.service_controller.active_sessions

    def get_session_stats(self, session_id: str) -> Optional[SessionStats]:
        """Get stats for a session."""
        return self.access_logger.get_session_stats(session_id)


async def main():
    """Main entry point for Network Actor agent."""
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )

    # Load config
    config = NetworkActorConfig.from_env()

    # Create agent
    agent = NetworkActorAgent(config)

    # Handle signals
    loop = asyncio.get_event_loop()

    def signal_handler():
        asyncio.create_task(agent.stop())

    loop.add_signal_handler(signal.SIGINT, signal_handler)
    loop.add_signal_handler(signal.SIGTERM, signal_handler)

    # Start agent
    await agent.start()

    # Keep running until stopped
    try:
        while agent._running:
            await asyncio.sleep(1)
    except asyncio.CancelledError:
        pass

    await agent.stop()


if __name__ == "__main__":
    asyncio.run(main())
