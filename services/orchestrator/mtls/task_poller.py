# Mirqab Cloud Relay - Task Poller
"""
Task polling service that fetches attack tasks from OffenSight Master.

Implements long-polling with exponential backoff for efficient task retrieval.
"""

import asyncio
import logging
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Optional, Callable, Awaitable
from enum import Enum

from .client import MTLSClient

logger = logging.getLogger(__name__)


class TaskStatus(str, Enum):
    """Task execution status."""
    PENDING = "pending"
    CLAIMED = "claimed"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


@dataclass
class AttackTask:
    """Represents an attack task from the Master."""
    task_id: str
    execution_id: str
    tenant_id: str
    attack_id: str
    attack_name: str
    step_id: str
    step_name: str
    parameters: dict
    target_domain: Optional[str] = None
    timeout_seconds: int = 300
    priority: int = 0
    created_at: Optional[datetime] = None
    claimed_at: Optional[datetime] = None

    @classmethod
    def from_dict(cls, data: dict) -> "AttackTask":
        """Create AttackTask from API response."""
        return cls(
            task_id=data["task_id"],
            execution_id=data["execution_id"],
            tenant_id=data["tenant_id"],
            attack_id=data["attack_id"],
            attack_name=data.get("attack_name", ""),
            step_id=data["step_id"],
            step_name=data.get("step_name", ""),
            parameters=data.get("parameters", {}),
            target_domain=data.get("target_domain"),
            timeout_seconds=data.get("timeout_seconds", 300),
            priority=data.get("priority", 0),
            created_at=datetime.fromisoformat(data["created_at"]) if data.get("created_at") else None,
            claimed_at=datetime.fromisoformat(data["claimed_at"]) if data.get("claimed_at") else None,
        )


# Type for task handler callback
TaskHandler = Callable[[AttackTask], Awaitable[dict]]


class TaskPoller:
    """
    Polls for attack tasks from OffenSight Master.

    Features:
    - Long-polling with configurable intervals
    - Exponential backoff on errors
    - Concurrent task execution (up to max_concurrent)
    - Graceful shutdown support
    """

    def __init__(
        self,
        client: MTLSClient,
        task_handler: TaskHandler,
        poll_interval_seconds: float = 5.0,
        max_poll_interval_seconds: float = 60.0,
        max_concurrent_tasks: int = 5,
    ):
        self.client = client
        self.task_handler = task_handler
        self.poll_interval = poll_interval_seconds
        self.max_poll_interval = max_poll_interval_seconds
        self.max_concurrent = max_concurrent_tasks

        self._running = False
        self._current_interval = poll_interval_seconds
        self._active_tasks: dict[str, asyncio.Task] = {}
        self._semaphore = asyncio.Semaphore(max_concurrent_tasks)
        self._poll_task: Optional[asyncio.Task] = None

    @property
    def is_running(self) -> bool:
        """Check if poller is running."""
        return self._running

    @property
    def active_task_count(self) -> int:
        """Get number of currently active tasks."""
        return len(self._active_tasks)

    async def start(self) -> None:
        """Start the task poller."""
        if self._running:
            return

        self._running = True
        self._current_interval = self.poll_interval
        self._poll_task = asyncio.create_task(self._poll_loop())
        logger.info(f"Task poller started (interval: {self.poll_interval}s, max_concurrent: {self.max_concurrent})")

    async def stop(self, timeout: float = 30.0) -> None:
        """Stop the task poller gracefully."""
        if not self._running:
            return

        self._running = False

        # Cancel poll task
        if self._poll_task:
            self._poll_task.cancel()
            try:
                await asyncio.wait_for(self._poll_task, timeout=5.0)
            except (asyncio.CancelledError, asyncio.TimeoutError):
                pass

        # Wait for active tasks to complete
        if self._active_tasks:
            logger.info(f"Waiting for {len(self._active_tasks)} active tasks to complete...")
            try:
                await asyncio.wait_for(
                    asyncio.gather(*self._active_tasks.values(), return_exceptions=True),
                    timeout=timeout,
                )
            except asyncio.TimeoutError:
                logger.warning("Timeout waiting for active tasks, cancelling...")
                for task in self._active_tasks.values():
                    task.cancel()

        self._active_tasks.clear()
        logger.info("Task poller stopped")

    async def _poll_loop(self) -> None:
        """Main polling loop."""
        consecutive_errors = 0

        while self._running:
            try:
                # Check if we can accept more tasks
                if self.active_task_count >= self.max_concurrent:
                    logger.debug(f"At max capacity ({self.max_concurrent}), skipping poll")
                    await asyncio.sleep(self._current_interval)
                    continue

                # Poll for tasks
                tasks = await self.client.poll_tasks()

                if tasks:
                    logger.info(f"Received {len(tasks)} task(s) from Master")
                    consecutive_errors = 0
                    self._current_interval = self.poll_interval

                    # Process each task
                    for task_data in tasks:
                        if not self._running:
                            break

                        if self.active_task_count >= self.max_concurrent:
                            logger.debug("Reached max capacity, deferring remaining tasks")
                            break

                        task = AttackTask.from_dict(task_data)
                        await self._handle_task(task)
                else:
                    # No tasks, apply backoff
                    self._current_interval = min(
                        self._current_interval * 1.5,
                        self.max_poll_interval,
                    )

            except asyncio.CancelledError:
                break
            except Exception as e:
                consecutive_errors += 1
                logger.error(f"Poll error (attempt {consecutive_errors}): {e}")

                # Exponential backoff on errors
                backoff = min(
                    self.poll_interval * (2 ** consecutive_errors),
                    self.max_poll_interval,
                )
                self._current_interval = backoff

            await asyncio.sleep(self._current_interval)

    async def _handle_task(self, task: AttackTask) -> None:
        """Handle a single task by claiming and executing it."""
        try:
            # Claim the task
            await self.client.claim_task(task.task_id)
            task.claimed_at = datetime.now(timezone.utc)
            logger.info(f"Claimed task {task.task_id} ({task.attack_name})")

            # Execute in background
            async def execute_task():
                async with self._semaphore:
                    try:
                        await self.client.update_task_status(
                            task.task_id,
                            TaskStatus.RUNNING.value,
                            progress=0,
                        )

                        # Execute with timeout
                        result = await asyncio.wait_for(
                            self.task_handler(task),
                            timeout=task.timeout_seconds,
                        )

                        await self.client.update_task_status(
                            task.task_id,
                            TaskStatus.COMPLETED.value,
                            progress=100,
                        )

                        # Report result
                        await self.client.report_result(
                            task.task_id,
                            task.execution_id,
                            task.step_id,
                            result,
                        )

                        logger.info(f"Task {task.task_id} completed successfully")

                    except asyncio.TimeoutError:
                        logger.error(f"Task {task.task_id} timed out after {task.timeout_seconds}s")
                        await self.client.update_task_status(
                            task.task_id,
                            TaskStatus.FAILED.value,
                            message=f"Timeout after {task.timeout_seconds}s",
                        )

                    except Exception as e:
                        logger.error(f"Task {task.task_id} failed: {e}")
                        await self.client.update_task_status(
                            task.task_id,
                            TaskStatus.FAILED.value,
                            message=str(e),
                        )

                    finally:
                        self._active_tasks.pop(task.task_id, None)

            # Start background execution
            self._active_tasks[task.task_id] = asyncio.create_task(execute_task())

        except Exception as e:
            logger.error(f"Failed to claim task {task.task_id}: {e}")
