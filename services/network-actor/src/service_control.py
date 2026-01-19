# Mirqab Cloud Relay - Service Control Module
"""
Service controller for Network Actor agents.

Manages starting/stopping of services like SMB, RDP, SSH, HTTP
with source IP restrictions and auto-timeout.
"""

import asyncio
import logging
import subprocess
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Optional, Callable, Awaitable

logger = logging.getLogger(__name__)


class ServiceType(str, Enum):
    """Supported service types."""
    SMB = "smb"
    RDP = "rdp"
    SSH = "ssh"
    HTTP = "http"
    HTTPS = "https"


class ServiceState(str, Enum):
    """Service state."""
    STOPPED = "stopped"
    STARTING = "starting"
    RUNNING = "running"
    STOPPING = "stopping"
    ERROR = "error"


@dataclass
class ServiceConfig:
    """Configuration for a service."""
    service_type: ServiceType
    port: int
    systemd_unit: Optional[str] = None
    docker_container: Optional[str] = None
    custom_start_cmd: Optional[str] = None
    custom_stop_cmd: Optional[str] = None
    health_check_cmd: Optional[str] = None


# Default service configurations
DEFAULT_SERVICES: dict[ServiceType, ServiceConfig] = {
    ServiceType.SMB: ServiceConfig(
        service_type=ServiceType.SMB,
        port=445,
        systemd_unit="smbd",
        health_check_cmd="smbclient -L localhost -N",
    ),
    ServiceType.RDP: ServiceConfig(
        service_type=ServiceType.RDP,
        port=3389,
        systemd_unit="xrdp",
        health_check_cmd="netstat -tlnp | grep :3389",
    ),
    ServiceType.SSH: ServiceConfig(
        service_type=ServiceType.SSH,
        port=22,
        systemd_unit="ssh",
        health_check_cmd="systemctl is-active ssh",
    ),
    ServiceType.HTTP: ServiceConfig(
        service_type=ServiceType.HTTP,
        port=80,
        systemd_unit="nginx",
        health_check_cmd="curl -s -o /dev/null -w '%{http_code}' http://localhost:80",
    ),
    ServiceType.HTTPS: ServiceConfig(
        service_type=ServiceType.HTTPS,
        port=443,
        systemd_unit="nginx",
        health_check_cmd="curl -sk -o /dev/null -w '%{http_code}' https://localhost:443",
    ),
}


@dataclass
class ServiceSession:
    """Active service session."""
    session_id: str
    service_type: ServiceType
    allowed_source_ip: str
    state: ServiceState = ServiceState.STOPPED
    started_at: Optional[datetime] = None
    timeout_at: Optional[datetime] = None
    task_id: Optional[str] = None
    execution_id: Optional[str] = None
    access_count: int = 0
    bytes_transferred: int = 0


class ServiceController:
    """
    Controller for managing service lifecycle.

    Features:
    - Start/stop services on demand
    - Source IP restrictions via firewall
    - Auto-timeout enforcement
    - Service health monitoring
    """

    def __init__(
        self,
        firewall_manager: "FirewallManager",
        access_logger: "AccessLogger",
        default_timeout_seconds: int = 300,
        max_timeout_seconds: int = 3600,
    ):
        self.firewall_manager = firewall_manager
        self.access_logger = access_logger
        self.default_timeout = default_timeout_seconds
        self.max_timeout = max_timeout_seconds

        self._sessions: dict[str, ServiceSession] = {}
        self._timeout_tasks: dict[str, asyncio.Task] = {}
        self._running = False
        self._service_configs = DEFAULT_SERVICES.copy()

    @property
    def active_sessions(self) -> list[ServiceSession]:
        """Get all active sessions."""
        return [
            s for s in self._sessions.values()
            if s.state in (ServiceState.STARTING, ServiceState.RUNNING)
        ]

    def get_session(self, session_id: str) -> Optional[ServiceSession]:
        """Get session by ID."""
        return self._sessions.get(session_id)

    async def start_service(
        self,
        session_id: str,
        service_type: ServiceType,
        allowed_source_ip: str,
        timeout_seconds: Optional[int] = None,
        task_id: Optional[str] = None,
        execution_id: Optional[str] = None,
    ) -> ServiceSession:
        """
        Start a service for a specific session.

        Args:
            session_id: Unique session identifier
            service_type: Type of service to start
            allowed_source_ip: Only allow connections from this IP
            timeout_seconds: Auto-close after this duration
            task_id: Associated task ID
            execution_id: Associated execution ID

        Returns:
            ServiceSession with current state
        """
        # Validate timeout
        timeout = timeout_seconds or self.default_timeout
        if timeout > self.max_timeout:
            timeout = self.max_timeout
            logger.warning(f"Timeout capped to max: {self.max_timeout}s")

        # Check for existing session
        if session_id in self._sessions:
            existing = self._sessions[session_id]
            if existing.state == ServiceState.RUNNING:
                logger.info(f"Session {session_id} already running")
                return existing

        # Get service config
        config = self._service_configs.get(service_type)
        if not config:
            raise ValueError(f"Unsupported service type: {service_type}")

        # Create session
        now = datetime.now(timezone.utc)
        session = ServiceSession(
            session_id=session_id,
            service_type=service_type,
            allowed_source_ip=allowed_source_ip,
            state=ServiceState.STARTING,
            started_at=now,
            timeout_at=now + timedelta(seconds=timeout),
            task_id=task_id,
            execution_id=execution_id,
        )
        self._sessions[session_id] = session

        try:
            # Add firewall rule (source-restricted)
            await self.firewall_manager.add_rule(
                rule_id=session_id,
                port=config.port,
                source_ip=allowed_source_ip,
                protocol="tcp",
            )
            logger.info(f"Firewall rule added for {session_id}: {config.port}/tcp from {allowed_source_ip}")

            # Start the service
            await self._start_system_service(config)
            logger.info(f"Service {service_type.value} started for session {session_id}")

            # Update state
            session.state = ServiceState.RUNNING

            # Schedule timeout
            self._timeout_tasks[session_id] = asyncio.create_task(
                self._enforce_timeout(session_id, timeout)
            )

            # Log access
            await self.access_logger.log_service_start(
                session_id=session_id,
                service_type=service_type,
                source_ip=allowed_source_ip,
                port=config.port,
            )

            return session

        except Exception as e:
            logger.error(f"Failed to start service: {e}")
            session.state = ServiceState.ERROR
            # Cleanup on failure
            await self._cleanup_session(session_id)
            raise

    async def stop_service(self, session_id: str, reason: str = "manual") -> ServiceSession:
        """
        Stop a service session.

        Args:
            session_id: Session to stop
            reason: Reason for stopping (manual, timeout, error)

        Returns:
            Updated ServiceSession
        """
        session = self._sessions.get(session_id)
        if not session:
            raise ValueError(f"Session not found: {session_id}")

        if session.state in (ServiceState.STOPPED, ServiceState.STOPPING):
            return session

        session.state = ServiceState.STOPPING
        logger.info(f"Stopping service for session {session_id}: {reason}")

        try:
            # Cancel timeout task
            if session_id in self._timeout_tasks:
                self._timeout_tasks[session_id].cancel()
                del self._timeout_tasks[session_id]

            # Remove firewall rule
            await self.firewall_manager.remove_rule(session_id)

            # Log access end
            await self.access_logger.log_service_stop(
                session_id=session_id,
                service_type=session.service_type,
                source_ip=session.allowed_source_ip,
                reason=reason,
                duration_seconds=(datetime.now(timezone.utc) - session.started_at).total_seconds()
                if session.started_at else 0,
                access_count=session.access_count,
            )

            session.state = ServiceState.STOPPED
            return session

        except Exception as e:
            logger.error(f"Error stopping service: {e}")
            session.state = ServiceState.ERROR
            raise

    async def _start_system_service(self, config: ServiceConfig) -> None:
        """Start the actual system service."""
        if config.custom_start_cmd:
            await self._run_command(config.custom_start_cmd)
        elif config.systemd_unit:
            await self._run_command(f"systemctl start {config.systemd_unit}")
        elif config.docker_container:
            await self._run_command(f"docker start {config.docker_container}")
        else:
            raise ValueError(f"No start method for service: {config.service_type}")

    async def _stop_system_service(self, config: ServiceConfig) -> None:
        """Stop the actual system service."""
        if config.custom_stop_cmd:
            await self._run_command(config.custom_stop_cmd)
        elif config.systemd_unit:
            await self._run_command(f"systemctl stop {config.systemd_unit}")
        elif config.docker_container:
            await self._run_command(f"docker stop {config.docker_container}")

    async def _run_command(self, cmd: str) -> tuple[int, str, str]:
        """Run a shell command asynchronously."""
        proc = await asyncio.create_subprocess_shell(
            cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await proc.communicate()
        return proc.returncode, stdout.decode(), stderr.decode()

    async def _enforce_timeout(self, session_id: str, timeout_seconds: int) -> None:
        """Wait for timeout then stop the service."""
        try:
            await asyncio.sleep(timeout_seconds)
            logger.info(f"Session {session_id} timed out after {timeout_seconds}s")
            await self.stop_service(session_id, reason="timeout")
        except asyncio.CancelledError:
            pass

    async def _cleanup_session(self, session_id: str) -> None:
        """Clean up a failed or completed session."""
        try:
            await self.firewall_manager.remove_rule(session_id)
        except Exception:
            pass

        if session_id in self._timeout_tasks:
            self._timeout_tasks[session_id].cancel()
            del self._timeout_tasks[session_id]

    async def stop_all(self) -> None:
        """Stop all active sessions."""
        for session_id in list(self._sessions.keys()):
            session = self._sessions[session_id]
            if session.state == ServiceState.RUNNING:
                await self.stop_service(session_id, reason="shutdown")

    async def health_check(self, service_type: ServiceType) -> bool:
        """Check if a service is healthy."""
        config = self._service_configs.get(service_type)
        if not config or not config.health_check_cmd:
            return False

        returncode, _, _ = await self._run_command(config.health_check_cmd)
        return returncode == 0
