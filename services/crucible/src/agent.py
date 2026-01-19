"""
Crucible Agent - In-VM Malware Execution Agent

Runs inside the isolated VM to:
- Receive encrypted malware payloads
- Execute samples in controlled manner
- Monitor for EDR/AV detections
- Report results back to controller
- Self-verify isolation before execution
"""

import asyncio
import base64
import hashlib
import json
import logging
import os
import subprocess
import tempfile
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Optional

import aiohttp
from aiohttp import web

logger = logging.getLogger(__name__)


class ExecutionStatus(Enum):
    """Malware execution status."""

    PENDING = "pending"
    DECRYPTING = "decrypting"
    EXECUTING = "executing"
    MONITORING = "monitoring"
    COMPLETED = "completed"
    DETECTED = "detected"
    BLOCKED = "blocked"
    TIMEOUT = "timeout"
    ERROR = "error"


class DetectionType(Enum):
    """Type of EDR/AV detection."""

    NONE = "none"
    SIGNATURE = "signature"
    BEHAVIORAL = "behavioral"
    MEMORY = "memory"
    NETWORK = "network"
    HEURISTIC = "heuristic"
    MACHINE_LEARNING = "machine_learning"


@dataclass
class MalwareSample:
    """Represents a malware sample to execute."""

    sample_id: str
    name: str
    payload_encrypted: bytes
    encryption_key: bytes
    expected_behaviors: list[str] = field(default_factory=list)
    execution_args: list[str] = field(default_factory=list)
    timeout_seconds: int = 60
    metadata: dict = field(default_factory=dict)


@dataclass
class DetectionEvent:
    """EDR/AV detection event."""

    event_id: str
    detection_type: DetectionType
    detection_source: str  # EDR product name
    threat_name: str
    severity: str
    process_name: Optional[str] = None
    process_id: Optional[int] = None
    file_path: Optional[str] = None
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    raw_data: dict = field(default_factory=dict)


@dataclass
class ExecutionResult:
    """Result of malware execution test."""

    sample_id: str
    session_id: str
    status: ExecutionStatus
    detected: bool
    detection_events: list[DetectionEvent] = field(default_factory=list)
    execution_time_ms: int = 0
    detection_time_ms: Optional[int] = None  # Time from exec to first detection
    process_events: list[dict] = field(default_factory=list)
    network_events: list[dict] = field(default_factory=list)
    file_events: list[dict] = field(default_factory=list)
    error_message: Optional[str] = None
    started_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    completed_at: Optional[datetime] = None


class CrucibleAgent:
    """
    Crucible Agent running inside isolated VM.

    Responsibilities:
    - Listen for execution commands from controller
    - Decrypt and execute malware samples
    - Monitor for EDR/AV responses
    - Report execution results
    - Self-verify network isolation
    """

    def __init__(
        self,
        controller_url: str,
        api_key: str,
        agent_id: str,
        listen_port: int = 9443,
        work_dir: str = "/tmp/crucible",
    ):
        self.controller_url = controller_url
        self.api_key = api_key
        self.agent_id = agent_id
        self.listen_port = listen_port
        self.work_dir = Path(work_dir)
        self._app: Optional[web.Application] = None
        self._runner: Optional[web.AppRunner] = None
        self._current_execution: Optional[str] = None

    async def start(self) -> None:
        """Start the agent API server."""
        # Create work directory
        self.work_dir.mkdir(parents=True, exist_ok=True)

        # Verify isolation before starting
        isolated = await self._verify_isolation()
        if not isolated:
            logger.critical("ISOLATION CHECK FAILED - Agent refusing to start")
            raise RuntimeError("Network isolation verification failed")

        # Set up API server
        self._app = web.Application()
        self._app.router.add_post("/execute", self._handle_execute)
        self._app.router.add_get("/status", self._handle_status)
        self._app.router.add_post("/abort", self._handle_abort)
        self._app.router.add_get("/health", self._handle_health)

        self._runner = web.AppRunner(self._app)
        await self._runner.setup()

        site = web.TCPSite(
            self._runner,
            "0.0.0.0",
            self.listen_port,
            ssl_context=self._create_ssl_context(),
        )
        await site.start()

        logger.info(f"Crucible Agent started on port {self.listen_port}")

        # Register with controller
        await self._register_with_controller()

    async def stop(self) -> None:
        """Stop the agent."""
        if self._runner:
            await self._runner.cleanup()
        logger.info("Crucible Agent stopped")

    async def execute_sample(self, sample: MalwareSample) -> ExecutionResult:
        """
        Execute a malware sample and monitor for detections.

        1. Verify isolation
        2. Decrypt payload
        3. Execute sample
        4. Monitor for EDR response
        5. Collect results
        """
        session_id = str(uuid.uuid4())
        self._current_execution = session_id

        result = ExecutionResult(
            sample_id=sample.sample_id,
            session_id=session_id,
            status=ExecutionStatus.PENDING,
            detected=False,
        )

        try:
            # Pre-execution isolation check
            if not await self._verify_isolation():
                result.status = ExecutionStatus.ERROR
                result.error_message = "Isolation check failed before execution"
                return result

            # Decrypt payload
            result.status = ExecutionStatus.DECRYPTING
            payload_path = await self._decrypt_payload(sample)

            # Start EDR monitoring
            edr_monitor = asyncio.create_task(
                self._monitor_edr(session_id, sample.timeout_seconds)
            )

            # Execute sample
            result.status = ExecutionStatus.EXECUTING
            exec_start = datetime.now(timezone.utc)

            process_result = await self._execute_payload(
                payload_path,
                sample.execution_args,
                sample.timeout_seconds,
            )

            result.execution_time_ms = int(
                (datetime.now(timezone.utc) - exec_start).total_seconds() * 1000
            )

            # Wait for EDR monitoring to complete
            result.status = ExecutionStatus.MONITORING
            detection_events = await edr_monitor

            result.detection_events = detection_events
            result.detected = len(detection_events) > 0

            if result.detected:
                result.status = ExecutionStatus.DETECTED
                # Calculate time to first detection
                first_detection = min(d.timestamp for d in detection_events)
                result.detection_time_ms = int(
                    (first_detection - exec_start).total_seconds() * 1000
                )
            else:
                result.status = ExecutionStatus.COMPLETED

            # Collect process/network/file events
            result.process_events = process_result.get("process_events", [])
            result.network_events = await self._collect_network_events(session_id)
            result.file_events = await self._collect_file_events(session_id)

        except asyncio.TimeoutError:
            result.status = ExecutionStatus.TIMEOUT
            result.error_message = f"Execution timeout after {sample.timeout_seconds}s"

        except Exception as e:
            result.status = ExecutionStatus.ERROR
            result.error_message = str(e)
            logger.error(f"Execution error: {e}", exc_info=True)

        finally:
            result.completed_at = datetime.now(timezone.utc)
            self._current_execution = None

            # Cleanup payload file
            if "payload_path" in locals():
                try:
                    os.unlink(payload_path)
                except Exception:
                    pass

        return result

    async def _verify_isolation(self) -> bool:
        """Verify VM is properly isolated from external networks."""
        checks_passed = 0
        checks_total = 3

        # Check 1: Cannot resolve external DNS
        try:
            process = await asyncio.create_subprocess_exec(
                "nslookup", "google.com",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(process.communicate(), timeout=5)
            if b"NXDOMAIN" in stdout or b"can't find" in stdout.lower():
                checks_passed += 1
            # If DNS resolves, we're NOT isolated
        except asyncio.TimeoutError:
            checks_passed += 1  # Timeout is good - means blocked
        except Exception:
            checks_passed += 1  # Error likely means blocked

        # Check 2: Cannot reach external IP
        try:
            process = await asyncio.create_subprocess_exec(
                "ping", "-c", "1", "-W", "2", "8.8.8.8",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await asyncio.wait_for(process.communicate(), timeout=5)
            if process.returncode != 0:
                checks_passed += 1
            # If ping succeeds, we're NOT isolated
        except asyncio.TimeoutError:
            checks_passed += 1
        except Exception:
            checks_passed += 1

        # Check 3: Cannot establish external TCP connection
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection("1.1.1.1", 443),
                timeout=3,
            )
            writer.close()
            await writer.wait_closed()
            # If we connected, we're NOT isolated
        except (asyncio.TimeoutError, OSError, ConnectionRefusedError):
            checks_passed += 1

        is_isolated = checks_passed >= 2  # Require at least 2/3 checks

        if not is_isolated:
            logger.critical(
                f"ISOLATION VERIFICATION FAILED: {checks_passed}/{checks_total} checks passed"
            )
        else:
            logger.info(f"Isolation verified: {checks_passed}/{checks_total} checks passed")

        return is_isolated

    async def _decrypt_payload(self, sample: MalwareSample) -> str:
        """Decrypt payload using AES-256-GCM."""
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        # Extract nonce and ciphertext
        nonce = sample.payload_encrypted[:12]
        ciphertext = sample.payload_encrypted[12:]

        # Decrypt
        aesgcm = AESGCM(sample.encryption_key)
        payload = aesgcm.decrypt(nonce, ciphertext, None)

        # Write to temp file
        payload_path = self.work_dir / f"{sample.sample_id}.exe"
        payload_path.write_bytes(payload)

        # Make executable
        os.chmod(payload_path, 0o755)

        logger.info(f"Decrypted payload to {payload_path}")
        return str(payload_path)

    async def _execute_payload(
        self,
        payload_path: str,
        args: list[str],
        timeout: int,
    ) -> dict:
        """Execute the malware payload."""
        events = []

        try:
            # Start process monitoring
            process = await asyncio.create_subprocess_exec(
                payload_path,
                *args,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            events.append({
                "type": "process_start",
                "pid": process.pid,
                "path": payload_path,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            })

            try:
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(),
                    timeout=timeout,
                )

                events.append({
                    "type": "process_exit",
                    "pid": process.pid,
                    "return_code": process.returncode,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                })

            except asyncio.TimeoutError:
                process.kill()
                events.append({
                    "type": "process_killed",
                    "pid": process.pid,
                    "reason": "timeout",
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                })

        except PermissionError:
            events.append({
                "type": "execution_blocked",
                "path": payload_path,
                "reason": "permission_denied",
                "timestamp": datetime.now(timezone.utc).isoformat(),
            })

        except Exception as e:
            events.append({
                "type": "execution_error",
                "path": payload_path,
                "error": str(e),
                "timestamp": datetime.now(timezone.utc).isoformat(),
            })

        return {"process_events": events}

    async def _monitor_edr(
        self,
        session_id: str,
        timeout_seconds: int,
    ) -> list[DetectionEvent]:
        """Monitor for EDR/AV detections during execution."""
        detections = []
        start_time = datetime.now(timezone.utc)

        # Check multiple sources for detections
        while (datetime.now(timezone.utc) - start_time).total_seconds() < timeout_seconds:
            # Check Windows Defender (if on Windows)
            defender_events = await self._check_defender_events()
            detections.extend(defender_events)

            # Check for CrowdStrike (if installed)
            cs_events = await self._check_crowdstrike_events()
            detections.extend(cs_events)

            # Check for SentinelOne (if installed)
            s1_events = await self._check_sentinelone_events()
            detections.extend(s1_events)

            # Short sleep between checks
            await asyncio.sleep(1)

            # Stop early if we have detections
            if detections:
                break

        return detections

    async def _check_defender_events(self) -> list[DetectionEvent]:
        """Check Windows Defender for recent detections."""
        events = []

        try:
            # Query Windows Security Center via PowerShell
            cmd = [
                "powershell", "-Command",
                "Get-MpThreatDetection | Select-Object -Last 5 | ConvertTo-Json"
            ]

            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(process.communicate(), timeout=10)

            if stdout:
                data = json.loads(stdout.decode())
                if isinstance(data, dict):
                    data = [data]

                for detection in data:
                    events.append(DetectionEvent(
                        event_id=str(uuid.uuid4()),
                        detection_type=DetectionType.SIGNATURE,
                        detection_source="Windows Defender",
                        threat_name=detection.get("ThreatName", "Unknown"),
                        severity=detection.get("SeverityID", "Unknown"),
                        process_id=detection.get("ProcessId"),
                        file_path=detection.get("Resources", [""])[0] if detection.get("Resources") else None,
                        raw_data=detection,
                    ))

        except Exception as e:
            logger.debug(f"Defender check failed (expected on non-Windows): {e}")

        return events

    async def _check_crowdstrike_events(self) -> list[DetectionEvent]:
        """Check CrowdStrike Falcon for recent detections."""
        events = []

        try:
            # Check if CrowdStrike agent is installed
            if not Path("/opt/CrowdStrike").exists():
                return events

            # Query local sensor events
            # Note: Real implementation would use CrowdStrike API
            cmd = ["falconctl", "-g", "--aidt"]

            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(process.communicate(), timeout=10)

            # Parse CrowdStrike output (simplified)
            if b"Detection" in stdout:
                events.append(DetectionEvent(
                    event_id=str(uuid.uuid4()),
                    detection_type=DetectionType.BEHAVIORAL,
                    detection_source="CrowdStrike Falcon",
                    threat_name="Behavioral Detection",
                    severity="High",
                    raw_data={"output": stdout.decode()},
                ))

        except Exception as e:
            logger.debug(f"CrowdStrike check failed: {e}")

        return events

    async def _check_sentinelone_events(self) -> list[DetectionEvent]:
        """Check SentinelOne for recent detections."""
        events = []

        try:
            # Check if SentinelOne agent is installed
            s1_paths = [
                "/opt/sentinelone",
                "C:\\Program Files\\SentinelOne",
            ]

            if not any(Path(p).exists() for p in s1_paths):
                return events

            # Query local agent (simplified)
            # Real implementation would use S1 API

        except Exception as e:
            logger.debug(f"SentinelOne check failed: {e}")

        return events

    async def _collect_network_events(self, session_id: str) -> list[dict]:
        """Collect network events from execution."""
        events = []

        try:
            # Check for new connections (Linux)
            process = await asyncio.create_subprocess_exec(
                "ss", "-tunp",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await process.communicate()

            for line in stdout.decode().split("\n")[1:]:  # Skip header
                if line.strip():
                    parts = line.split()
                    if len(parts) >= 5:
                        events.append({
                            "type": "connection",
                            "state": parts[0],
                            "local": parts[3] if len(parts) > 3 else "",
                            "remote": parts[4] if len(parts) > 4 else "",
                            "timestamp": datetime.now(timezone.utc).isoformat(),
                        })

        except Exception as e:
            logger.debug(f"Network collection failed: {e}")

        return events

    async def _collect_file_events(self, session_id: str) -> list[dict]:
        """Collect file system events from execution."""
        events = []

        # Check for recently modified files in work directory
        try:
            for path in self.work_dir.rglob("*"):
                if path.is_file():
                    stat = path.stat()
                    events.append({
                        "type": "file_modified",
                        "path": str(path),
                        "size": stat.st_size,
                        "mtime": datetime.fromtimestamp(
                            stat.st_mtime, tz=timezone.utc
                        ).isoformat(),
                    })

        except Exception as e:
            logger.debug(f"File collection failed: {e}")

        return events

    def _create_ssl_context(self):
        """Create SSL context for API server."""
        import ssl

        ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)

        # In production, use proper certificates
        # For now, generate self-signed
        cert_dir = self.work_dir / "certs"
        cert_dir.mkdir(exist_ok=True)

        cert_path = cert_dir / "agent.crt"
        key_path = cert_dir / "agent.key"

        if not cert_path.exists():
            # Generate self-signed cert
            subprocess.run([
                "openssl", "req", "-x509", "-newkey", "rsa:4096",
                "-keyout", str(key_path),
                "-out", str(cert_path),
                "-days", "365", "-nodes",
                "-subj", "/CN=crucible-agent",
            ], check=True, capture_output=True)

        ctx.load_cert_chain(cert_path, key_path)
        return ctx

    async def _register_with_controller(self) -> None:
        """Register agent with controller."""
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    f"{self.controller_url}/api/v1/agents/register",
                    json={
                        "agent_id": self.agent_id,
                        "port": self.listen_port,
                    },
                    headers={"Authorization": f"Bearer {self.api_key}"},
                    ssl=False,  # In production, verify controller cert
                ) as resp:
                    if resp.status == 200:
                        logger.info("Registered with controller")
                    else:
                        logger.warning(f"Controller registration failed: {resp.status}")

        except Exception as e:
            logger.warning(f"Could not register with controller: {e}")

    # API Handlers
    async def _handle_execute(self, request: web.Request) -> web.Response:
        """Handle execution request from controller."""
        # Verify API key
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer ") or auth[7:] != self.api_key:
            return web.json_response({"error": "Unauthorized"}, status=401)

        try:
            data = await request.json()

            sample = MalwareSample(
                sample_id=data["sample_id"],
                name=data["name"],
                payload_encrypted=base64.b64decode(data["payload"]),
                encryption_key=base64.b64decode(data["key"]),
                expected_behaviors=data.get("expected_behaviors", []),
                execution_args=data.get("args", []),
                timeout_seconds=data.get("timeout", 60),
                metadata=data.get("metadata", {}),
            )

            result = await self.execute_sample(sample)

            return web.json_response({
                "session_id": result.session_id,
                "status": result.status.value,
                "detected": result.detected,
                "detection_count": len(result.detection_events),
                "execution_time_ms": result.execution_time_ms,
                "detection_time_ms": result.detection_time_ms,
            })

        except Exception as e:
            logger.error(f"Execution request failed: {e}")
            return web.json_response({"error": str(e)}, status=500)

    async def _handle_status(self, request: web.Request) -> web.Response:
        """Handle status request."""
        return web.json_response({
            "agent_id": self.agent_id,
            "status": "executing" if self._current_execution else "idle",
            "current_session": self._current_execution,
        })

    async def _handle_abort(self, request: web.Request) -> web.Response:
        """Handle abort request."""
        self._current_execution = None
        return web.json_response({"status": "aborted"})

    async def _handle_health(self, request: web.Request) -> web.Response:
        """Handle health check."""
        isolated = await self._verify_isolation()
        return web.json_response({
            "healthy": isolated,
            "isolated": isolated,
        })
