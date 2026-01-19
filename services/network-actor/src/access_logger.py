# Mirqab Cloud Relay - Access Logger Module
"""
Access logging for Network Actor services.

Features:
- Real-time access logging
- Structured log format for SIEM ingestion
- Connection tracking and statistics
- Reporting to Master server
"""

import asyncio
import logging
import json
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from typing import Optional, Callable, Awaitable
from pathlib import Path
import aiofiles

logger = logging.getLogger(__name__)


class AccessEventType(str, Enum):
    """Types of access events."""
    SERVICE_START = "service_start"
    SERVICE_STOP = "service_stop"
    CONNECTION_ATTEMPT = "connection_attempt"
    CONNECTION_ESTABLISHED = "connection_established"
    CONNECTION_CLOSED = "connection_closed"
    AUTHENTICATION_SUCCESS = "authentication_success"
    AUTHENTICATION_FAILURE = "authentication_failure"
    DATA_TRANSFER = "data_transfer"
    BLOCKED = "blocked"
    ERROR = "error"


@dataclass
class AccessLogEntry:
    """Single access log entry."""
    timestamp: datetime
    event_type: AccessEventType
    session_id: str
    service_type: str
    source_ip: str
    source_port: Optional[int] = None
    destination_port: int = 0
    username: Optional[str] = None
    action: Optional[str] = None
    bytes_sent: int = 0
    bytes_received: int = 0
    duration_seconds: float = 0.0
    message: Optional[str] = None
    metadata: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        data = asdict(self)
        data["timestamp"] = self.timestamp.isoformat()
        data["event_type"] = self.event_type.value
        return data

    def to_json(self) -> str:
        """Convert to JSON string."""
        return json.dumps(self.to_dict())


@dataclass
class SessionStats:
    """Statistics for a service session."""
    session_id: str
    service_type: str
    started_at: datetime
    ended_at: Optional[datetime] = None
    total_connections: int = 0
    successful_connections: int = 0
    failed_connections: int = 0
    authentication_successes: int = 0
    authentication_failures: int = 0
    total_bytes_sent: int = 0
    total_bytes_received: int = 0
    unique_source_ips: set = field(default_factory=set)
    blocked_attempts: int = 0

    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            "session_id": self.session_id,
            "service_type": self.service_type,
            "started_at": self.started_at.isoformat(),
            "ended_at": self.ended_at.isoformat() if self.ended_at else None,
            "duration_seconds": (self.ended_at - self.started_at).total_seconds()
            if self.ended_at else None,
            "total_connections": self.total_connections,
            "successful_connections": self.successful_connections,
            "failed_connections": self.failed_connections,
            "authentication_successes": self.authentication_successes,
            "authentication_failures": self.authentication_failures,
            "total_bytes_sent": self.total_bytes_sent,
            "total_bytes_received": self.total_bytes_received,
            "unique_source_ips": list(self.unique_source_ips),
            "blocked_attempts": self.blocked_attempts,
        }


# Type for report callback
ReportCallback = Callable[[dict], Awaitable[None]]


class AccessLogger:
    """
    Access logger for Network Actor services.

    Features:
    - Structured logging to file and stdout
    - Real-time statistics tracking
    - Session-based aggregation
    - Master server reporting
    """

    def __init__(
        self,
        log_dir: Path = Path("/var/log/mirqab-network-actor"),
        report_callback: Optional[ReportCallback] = None,
        buffer_size: int = 100,
    ):
        self.log_dir = log_dir
        self.report_callback = report_callback
        self.buffer_size = buffer_size

        self._session_stats: dict[str, SessionStats] = {}
        self._log_buffer: list[AccessLogEntry] = []
        self._flush_task: Optional[asyncio.Task] = None
        self._running = False
        self._log_file: Optional[aiofiles.threadpool.binary.AsyncBufferedIOBase] = None

    async def start(self) -> None:
        """Start the access logger."""
        if self._running:
            return

        # Ensure log directory exists
        self.log_dir.mkdir(parents=True, exist_ok=True)

        # Open log file
        log_path = self.log_dir / f"access-{datetime.now(timezone.utc).strftime('%Y%m%d')}.jsonl"
        self._log_file = await aiofiles.open(log_path, mode="a")

        # Start periodic flush task
        self._running = True
        self._flush_task = asyncio.create_task(self._periodic_flush())

        logger.info(f"Access logger started, logging to {log_path}")

    async def stop(self) -> None:
        """Stop the access logger."""
        if not self._running:
            return

        self._running = False

        # Cancel flush task
        if self._flush_task:
            self._flush_task.cancel()
            try:
                await self._flush_task
            except asyncio.CancelledError:
                pass

        # Flush remaining logs
        await self._flush_buffer()

        # Close log file
        if self._log_file:
            await self._log_file.close()
            self._log_file = None

        logger.info("Access logger stopped")

    async def _periodic_flush(self) -> None:
        """Periodically flush log buffer."""
        while self._running:
            await asyncio.sleep(5)  # Flush every 5 seconds
            await self._flush_buffer()

    async def _flush_buffer(self) -> None:
        """Flush buffered logs to file."""
        if not self._log_buffer or not self._log_file:
            return

        entries = self._log_buffer.copy()
        self._log_buffer.clear()

        for entry in entries:
            await self._log_file.write((entry.to_json() + "\n").encode())
        await self._log_file.flush()

    async def _add_entry(self, entry: AccessLogEntry) -> None:
        """Add a log entry to the buffer."""
        self._log_buffer.append(entry)

        # Flush if buffer is full
        if len(self._log_buffer) >= self.buffer_size:
            await self._flush_buffer()

        # Also log to standard logger
        logger.info(f"ACCESS: {entry.event_type.value} - {entry.session_id} - {entry.source_ip}")

    def _get_or_create_stats(self, session_id: str, service_type: str) -> SessionStats:
        """Get or create session stats."""
        if session_id not in self._session_stats:
            self._session_stats[session_id] = SessionStats(
                session_id=session_id,
                service_type=service_type,
                started_at=datetime.now(timezone.utc),
            )
        return self._session_stats[session_id]

    # ==========================================================================
    # Logging Methods
    # ==========================================================================

    async def log_service_start(
        self,
        session_id: str,
        service_type: str,
        source_ip: str,
        port: int,
    ) -> None:
        """Log service start event."""
        entry = AccessLogEntry(
            timestamp=datetime.now(timezone.utc),
            event_type=AccessEventType.SERVICE_START,
            session_id=session_id,
            service_type=service_type,
            source_ip=source_ip,
            destination_port=port,
            message=f"Service {service_type} started for {source_ip}",
        )
        await self._add_entry(entry)

        # Initialize session stats
        self._get_or_create_stats(session_id, service_type)

    async def log_service_stop(
        self,
        session_id: str,
        service_type: str,
        source_ip: str,
        reason: str,
        duration_seconds: float,
        access_count: int,
    ) -> None:
        """Log service stop event."""
        entry = AccessLogEntry(
            timestamp=datetime.now(timezone.utc),
            event_type=AccessEventType.SERVICE_STOP,
            session_id=session_id,
            service_type=service_type,
            source_ip=source_ip,
            duration_seconds=duration_seconds,
            message=f"Service stopped: {reason}",
            metadata={
                "reason": reason,
                "access_count": access_count,
            },
        )
        await self._add_entry(entry)

        # Finalize session stats
        if session_id in self._session_stats:
            stats = self._session_stats[session_id]
            stats.ended_at = datetime.now(timezone.utc)

            # Report to Master if callback configured
            if self.report_callback:
                await self._report_session(stats)

    async def log_connection_attempt(
        self,
        session_id: str,
        service_type: str,
        source_ip: str,
        source_port: int,
        destination_port: int,
        allowed: bool,
    ) -> None:
        """Log connection attempt."""
        entry = AccessLogEntry(
            timestamp=datetime.now(timezone.utc),
            event_type=AccessEventType.CONNECTION_ATTEMPT if allowed else AccessEventType.BLOCKED,
            session_id=session_id,
            service_type=service_type,
            source_ip=source_ip,
            source_port=source_port,
            destination_port=destination_port,
            message="Connection allowed" if allowed else "Connection blocked",
        )
        await self._add_entry(entry)

        # Update stats
        stats = self._get_or_create_stats(session_id, service_type)
        stats.total_connections += 1
        stats.unique_source_ips.add(source_ip)
        if not allowed:
            stats.blocked_attempts += 1

    async def log_connection_established(
        self,
        session_id: str,
        service_type: str,
        source_ip: str,
        source_port: int,
        destination_port: int,
        username: Optional[str] = None,
    ) -> None:
        """Log successful connection establishment."""
        entry = AccessLogEntry(
            timestamp=datetime.now(timezone.utc),
            event_type=AccessEventType.CONNECTION_ESTABLISHED,
            session_id=session_id,
            service_type=service_type,
            source_ip=source_ip,
            source_port=source_port,
            destination_port=destination_port,
            username=username,
            message=f"Connection established from {source_ip}:{source_port}",
        )
        await self._add_entry(entry)

        # Update stats
        stats = self._get_or_create_stats(session_id, service_type)
        stats.successful_connections += 1

    async def log_authentication(
        self,
        session_id: str,
        service_type: str,
        source_ip: str,
        username: str,
        success: bool,
        method: Optional[str] = None,
    ) -> None:
        """Log authentication attempt."""
        event_type = (
            AccessEventType.AUTHENTICATION_SUCCESS if success
            else AccessEventType.AUTHENTICATION_FAILURE
        )
        entry = AccessLogEntry(
            timestamp=datetime.now(timezone.utc),
            event_type=event_type,
            session_id=session_id,
            service_type=service_type,
            source_ip=source_ip,
            username=username,
            message=f"Auth {'success' if success else 'failure'}: {username}",
            metadata={"method": method} if method else {},
        )
        await self._add_entry(entry)

        # Update stats
        stats = self._get_or_create_stats(session_id, service_type)
        if success:
            stats.authentication_successes += 1
        else:
            stats.authentication_failures += 1

    async def log_data_transfer(
        self,
        session_id: str,
        service_type: str,
        source_ip: str,
        bytes_sent: int,
        bytes_received: int,
    ) -> None:
        """Log data transfer."""
        entry = AccessLogEntry(
            timestamp=datetime.now(timezone.utc),
            event_type=AccessEventType.DATA_TRANSFER,
            session_id=session_id,
            service_type=service_type,
            source_ip=source_ip,
            bytes_sent=bytes_sent,
            bytes_received=bytes_received,
            message=f"Transfer: {bytes_sent}B sent, {bytes_received}B received",
        )
        await self._add_entry(entry)

        # Update stats
        stats = self._get_or_create_stats(session_id, service_type)
        stats.total_bytes_sent += bytes_sent
        stats.total_bytes_received += bytes_received

    # ==========================================================================
    # Reporting
    # ==========================================================================

    async def _report_session(self, stats: SessionStats) -> None:
        """Report session stats to Master."""
        if not self.report_callback:
            return

        try:
            report = {
                "report_type": "network_actor_session",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "session": stats.to_dict(),
            }
            await self.report_callback(report)
            logger.info(f"Session report sent for {stats.session_id}")
        except Exception as e:
            logger.error(f"Failed to report session: {e}")

    def get_session_stats(self, session_id: str) -> Optional[SessionStats]:
        """Get stats for a session."""
        return self._session_stats.get(session_id)

    def get_all_stats(self) -> list[SessionStats]:
        """Get all session stats."""
        return list(self._session_stats.values())
