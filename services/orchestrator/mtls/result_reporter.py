# Mirqab Cloud Relay - Result Reporter
"""
Result reporting service that sends attack results back to OffenSight Master.

Handles batching, retries, and evidence collection.
"""

import asyncio
import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional, Any
from enum import Enum
import json

from .client import MTLSClient

logger = logging.getLogger(__name__)


class ResultOutcome(str, Enum):
    """Attack result outcome."""
    SUCCESS = "success"
    FAILURE = "failure"
    BLOCKED = "blocked"
    DETECTED = "detected"
    MISSED = "missed"
    TIMEOUT = "timeout"
    ERROR = "error"


@dataclass
class AttackResult:
    """Represents the result of an attack execution."""
    task_id: str
    execution_id: str
    step_id: str
    tenant_id: str

    # Execution details
    outcome: ResultOutcome
    command_executed: str
    command_output: str
    exit_code: int
    started_at: datetime
    completed_at: datetime
    duration_ms: int

    # Detection status
    blocked: bool = False
    detected: bool = False
    alerted: bool = False
    logged: bool = False

    # Evidence
    evidence: list[dict] = field(default_factory=list)
    error_message: Optional[str] = None

    def to_dict(self) -> dict:
        """Convert to dictionary for API submission."""
        return {
            "task_id": self.task_id,
            "execution_id": self.execution_id,
            "step_id": self.step_id,
            "tenant_id": self.tenant_id,
            "outcome": self.outcome.value,
            "command_executed": self.command_executed,
            "command_output": self.command_output,
            "exit_code": self.exit_code,
            "started_at": self.started_at.isoformat(),
            "completed_at": self.completed_at.isoformat(),
            "duration_ms": self.duration_ms,
            "blocked": self.blocked,
            "detected": self.detected,
            "alerted": self.alerted,
            "logged": self.logged,
            "evidence": self.evidence,
            "error_message": self.error_message,
        }


@dataclass
class WAFTestResult:
    """Represents the result of a WAF test."""
    task_id: str
    tenant_id: str
    target_domain: str
    test_category: str

    # Results
    total_payloads: int
    blocked_count: int
    passed_count: int
    error_count: int
    effectiveness_score: float

    # Detailed results
    payload_results: list[dict] = field(default_factory=list)
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None

    def to_dict(self) -> dict:
        """Convert to dictionary for API submission."""
        return {
            "task_id": self.task_id,
            "tenant_id": self.tenant_id,
            "target_domain": self.target_domain,
            "test_category": self.test_category,
            "total_payloads": self.total_payloads,
            "blocked_count": self.blocked_count,
            "passed_count": self.passed_count,
            "error_count": self.error_count,
            "effectiveness_score": self.effectiveness_score,
            "payload_results": self.payload_results,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
        }


@dataclass
class C2CallbackResult:
    """Represents a C2 callback event."""
    channel_id: str
    tenant_id: str
    callback_type: str  # http, dns, smb

    # Callback details
    source_ip: str
    source_port: int
    timestamp: datetime
    raw_data: bytes
    parsed_data: Optional[dict] = None

    # Agent info if available
    agent_id: Optional[str] = None
    execution_id: Optional[str] = None

    def to_dict(self) -> dict:
        """Convert to dictionary for API submission."""
        return {
            "channel_id": self.channel_id,
            "tenant_id": self.tenant_id,
            "callback_type": self.callback_type,
            "source_ip": self.source_ip,
            "source_port": self.source_port,
            "timestamp": self.timestamp.isoformat(),
            "raw_data_b64": self.raw_data.hex() if self.raw_data else None,
            "parsed_data": self.parsed_data,
            "agent_id": self.agent_id,
            "execution_id": self.execution_id,
        }


class ResultReporter:
    """
    Reports attack results, WAF tests, and C2 callbacks to OffenSight Master.

    Features:
    - Immediate reporting for critical results
    - Batched reporting for efficiency
    - Retry logic with exponential backoff
    - Evidence attachment support
    """

    def __init__(
        self,
        client: MTLSClient,
        batch_size: int = 10,
        batch_interval_seconds: float = 5.0,
        max_retries: int = 3,
    ):
        self.client = client
        self.batch_size = batch_size
        self.batch_interval = batch_interval_seconds
        self.max_retries = max_retries

        self._pending_results: list[AttackResult] = []
        self._pending_waf_results: list[WAFTestResult] = []
        self._pending_callbacks: list[C2CallbackResult] = []
        self._running = False
        self._batch_task: Optional[asyncio.Task] = None
        self._lock = asyncio.Lock()

    async def start(self) -> None:
        """Start the batch reporter."""
        if self._running:
            return

        self._running = True
        self._batch_task = asyncio.create_task(self._batch_loop())
        logger.info("Result reporter started")

    async def stop(self, timeout: float = 30.0) -> None:
        """Stop the reporter and flush pending results."""
        if not self._running:
            return

        self._running = False

        # Cancel batch task
        if self._batch_task:
            self._batch_task.cancel()
            try:
                await asyncio.wait_for(self._batch_task, timeout=5.0)
            except (asyncio.CancelledError, asyncio.TimeoutError):
                pass

        # Flush remaining results
        await self._flush_all()
        logger.info("Result reporter stopped")

    async def report_attack_result(self, result: AttackResult, immediate: bool = False) -> bool:
        """Report an attack result."""
        if immediate:
            return await self._send_attack_result(result)

        async with self._lock:
            self._pending_results.append(result)

            if len(self._pending_results) >= self.batch_size:
                await self._flush_attack_results()

        return True

    async def report_waf_result(self, result: WAFTestResult, immediate: bool = True) -> bool:
        """Report a WAF test result (defaults to immediate)."""
        if immediate:
            return await self._send_waf_result(result)

        async with self._lock:
            self._pending_waf_results.append(result)

        return True

    async def report_c2_callback(self, callback: C2CallbackResult, immediate: bool = True) -> bool:
        """Report a C2 callback (defaults to immediate)."""
        if immediate:
            return await self._send_c2_callback(callback)

        async with self._lock:
            self._pending_callbacks.append(callback)

        return True

    async def _batch_loop(self) -> None:
        """Periodic batch flush loop."""
        while self._running:
            try:
                await asyncio.sleep(self.batch_interval)
                await self._flush_all()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Batch flush error: {e}")

    async def _flush_all(self) -> None:
        """Flush all pending results."""
        async with self._lock:
            if self._pending_results:
                await self._flush_attack_results()
            if self._pending_waf_results:
                await self._flush_waf_results()
            if self._pending_callbacks:
                await self._flush_callbacks()

    async def _flush_attack_results(self) -> None:
        """Flush pending attack results."""
        results = self._pending_results[:]
        self._pending_results.clear()

        for result in results:
            try:
                await self._send_attack_result(result)
            except Exception as e:
                logger.error(f"Failed to send attack result {result.task_id}: {e}")
                # Re-queue for retry
                self._pending_results.append(result)

    async def _flush_waf_results(self) -> None:
        """Flush pending WAF results."""
        results = self._pending_waf_results[:]
        self._pending_waf_results.clear()

        for result in results:
            try:
                await self._send_waf_result(result)
            except Exception as e:
                logger.error(f"Failed to send WAF result {result.task_id}: {e}")

    async def _flush_callbacks(self) -> None:
        """Flush pending C2 callbacks."""
        callbacks = self._pending_callbacks[:]
        self._pending_callbacks.clear()

        for callback in callbacks:
            try:
                await self._send_c2_callback(callback)
            except Exception as e:
                logger.error(f"Failed to send C2 callback {callback.channel_id}: {e}")

    async def _send_attack_result(self, result: AttackResult) -> bool:
        """Send a single attack result with retry."""
        for attempt in range(self.max_retries):
            try:
                await self.client.report_result(
                    result.task_id,
                    result.execution_id,
                    result.step_id,
                    result.to_dict(),
                )

                # Also report evidence if present
                for evidence in result.evidence:
                    await self.client.report_evidence(
                        result.task_id,
                        result.execution_id,
                        evidence.get("type", "unknown"),
                        evidence,
                    )

                logger.debug(f"Reported attack result {result.task_id}")
                return True

            except Exception as e:
                logger.warning(f"Failed to send attack result (attempt {attempt + 1}): {e}")
                await asyncio.sleep(2 ** attempt)

        return False

    async def _send_waf_result(self, result: WAFTestResult) -> bool:
        """Send a WAF test result with retry."""
        for attempt in range(self.max_retries):
            try:
                await self.client._request(
                    "POST",
                    f"/api/v1/cloud-relay/waf-test/{result.task_id}/result",
                    data=result.to_dict(),
                )
                logger.debug(f"Reported WAF result {result.task_id}")
                return True

            except Exception as e:
                logger.warning(f"Failed to send WAF result (attempt {attempt + 1}): {e}")
                await asyncio.sleep(2 ** attempt)

        return False

    async def _send_c2_callback(self, callback: C2CallbackResult) -> bool:
        """Send a C2 callback with retry."""
        for attempt in range(self.max_retries):
            try:
                await self.client.report_c2_callback(
                    callback.channel_id,
                    callback.to_dict(),
                )
                logger.debug(f"Reported C2 callback {callback.channel_id}")
                return True

            except Exception as e:
                logger.warning(f"Failed to send C2 callback (attempt {attempt + 1}): {e}")
                await asyncio.sleep(2 ** attempt)

        return False
