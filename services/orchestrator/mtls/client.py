# Mirqab Cloud Relay - mTLS Client
"""
mTLS HTTP client for secure communication with OffenSight Master.

Implements mutual TLS authentication using client certificates.
"""

import ssl
import httpx
import logging
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional, Any
from datetime import datetime, timedelta
import asyncio
import json

logger = logging.getLogger(__name__)


@dataclass
class MTLSConfig:
    """Configuration for mTLS connection to Master."""

    # Master server URL
    master_url: str

    # Tenant identification
    tenant_id: str
    api_key: str

    # Certificate paths
    client_cert_path: Path
    client_key_path: Path
    ca_cert_path: Path

    # Connection settings
    timeout_seconds: float = 30.0
    max_retries: int = 3
    retry_delay_seconds: float = 5.0

    # Certificate validation
    verify_hostname: bool = True
    check_hostname: bool = True

    def __post_init__(self):
        """Validate configuration after initialization."""
        # Convert string paths to Path objects
        if isinstance(self.client_cert_path, str):
            self.client_cert_path = Path(self.client_cert_path)
        if isinstance(self.client_key_path, str):
            self.client_key_path = Path(self.client_key_path)
        if isinstance(self.ca_cert_path, str):
            self.ca_cert_path = Path(self.ca_cert_path)

    def validate(self) -> list[str]:
        """Validate configuration and return list of errors."""
        errors = []

        if not self.master_url:
            errors.append("master_url is required")
        if not self.tenant_id:
            errors.append("tenant_id is required")
        if not self.api_key:
            errors.append("api_key is required")

        if not self.client_cert_path.exists():
            errors.append(f"Client certificate not found: {self.client_cert_path}")
        if not self.client_key_path.exists():
            errors.append(f"Client key not found: {self.client_key_path}")
        if not self.ca_cert_path.exists():
            errors.append(f"CA certificate not found: {self.ca_cert_path}")

        return errors


class MTLSClient:
    """
    mTLS HTTP client for secure communication with OffenSight Master.

    Provides authenticated API calls using mutual TLS with client certificates.
    Handles connection pooling, retries, and error handling.
    """

    def __init__(self, config: MTLSConfig):
        self.config = config
        self._client: Optional[httpx.AsyncClient] = None
        self._ssl_context: Optional[ssl.SSLContext] = None
        self._last_health_check: Optional[datetime] = None
        self._connected: bool = False

    async def __aenter__(self) -> "MTLSClient":
        await self.connect()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.disconnect()

    def _create_ssl_context(self) -> ssl.SSLContext:
        """Create SSL context with client certificate authentication."""
        ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)

        # Load CA certificate for server verification
        ctx.load_verify_locations(str(self.config.ca_cert_path))

        # Load client certificate and key for mutual TLS
        ctx.load_cert_chain(
            certfile=str(self.config.client_cert_path),
            keyfile=str(self.config.client_key_path),
        )

        # Security settings
        ctx.check_hostname = self.config.check_hostname
        ctx.verify_mode = ssl.CERT_REQUIRED
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2

        # Disable insecure protocols and ciphers
        ctx.options |= ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3

        return ctx

    async def connect(self) -> None:
        """Establish mTLS connection to Master."""
        if self._client is not None:
            return

        # Validate configuration
        errors = self.config.validate()
        if errors:
            raise ValueError(f"Invalid mTLS configuration: {'; '.join(errors)}")

        # Create SSL context
        self._ssl_context = self._create_ssl_context()

        # Create async HTTP client with mTLS
        self._client = httpx.AsyncClient(
            base_url=self.config.master_url,
            verify=self._ssl_context,
            timeout=httpx.Timeout(self.config.timeout_seconds),
            headers={
                "X-Tenant-ID": self.config.tenant_id,
                "X-API-Key": self.config.api_key,
                "Content-Type": "application/json",
                "User-Agent": f"mirqab-cloud-relay/{self.config.tenant_id}",
            },
        )

        # Verify connection with health check
        try:
            await self.health_check()
            self._connected = True
            logger.info(f"Connected to Master via mTLS: {self.config.master_url}")
        except Exception as e:
            await self.disconnect()
            raise ConnectionError(f"Failed to connect to Master: {e}")

    async def disconnect(self) -> None:
        """Close mTLS connection."""
        if self._client is not None:
            await self._client.aclose()
            self._client = None
        self._connected = False
        logger.info("Disconnected from Master")

    @property
    def is_connected(self) -> bool:
        """Check if client is connected."""
        return self._connected and self._client is not None

    async def _request(
        self,
        method: str,
        endpoint: str,
        data: Optional[dict] = None,
        params: Optional[dict] = None,
    ) -> dict:
        """Make authenticated API request with retries."""
        if not self.is_connected:
            await self.connect()

        last_error = None
        for attempt in range(self.config.max_retries):
            try:
                response = await self._client.request(
                    method=method,
                    url=endpoint,
                    json=data,
                    params=params,
                )

                response.raise_for_status()
                return response.json()

            except httpx.HTTPStatusError as e:
                logger.warning(f"HTTP error {e.response.status_code}: {e.response.text}")
                last_error = e

                # Don't retry on client errors (4xx)
                if 400 <= e.response.status_code < 500:
                    raise

            except (httpx.ConnectError, httpx.TimeoutException) as e:
                logger.warning(f"Connection error (attempt {attempt + 1}): {e}")
                last_error = e

                # Reconnect on next attempt
                self._connected = False
                await asyncio.sleep(self.config.retry_delay_seconds)

        raise last_error or ConnectionError("Request failed after retries")

    async def health_check(self) -> dict:
        """Check Master server health."""
        result = await self._request("GET", "/api/v1/health")
        self._last_health_check = datetime.utcnow()
        return result

    # ==========================================================================
    # Task Polling API
    # ==========================================================================

    async def poll_tasks(self) -> list[dict]:
        """Poll for pending attack tasks assigned to this tenant."""
        result = await self._request(
            "GET",
            "/api/v1/cloud-relay/tasks/poll",
            params={"tenant_id": self.config.tenant_id},
        )
        return result.get("tasks", [])

    async def claim_task(self, task_id: str) -> dict:
        """Claim a task for execution."""
        return await self._request(
            "POST",
            f"/api/v1/cloud-relay/tasks/{task_id}/claim",
            data={"tenant_id": self.config.tenant_id},
        )

    async def update_task_status(
        self,
        task_id: str,
        status: str,
        progress: Optional[int] = None,
        message: Optional[str] = None,
    ) -> dict:
        """Update task execution status."""
        data = {
            "status": status,
            "tenant_id": self.config.tenant_id,
        }
        if progress is not None:
            data["progress"] = progress
        if message is not None:
            data["message"] = message

        return await self._request(
            "PATCH",
            f"/api/v1/cloud-relay/tasks/{task_id}/status",
            data=data,
        )

    # ==========================================================================
    # Result Reporting API
    # ==========================================================================

    async def report_result(
        self,
        task_id: str,
        execution_id: str,
        step_id: str,
        result: dict,
    ) -> dict:
        """Report attack execution result to Master."""
        return await self._request(
            "POST",
            f"/api/v1/cloud-relay/tasks/{task_id}/result",
            data={
                "tenant_id": self.config.tenant_id,
                "execution_id": execution_id,
                "step_id": step_id,
                "result": result,
            },
        )

    async def report_evidence(
        self,
        task_id: str,
        execution_id: str,
        evidence_type: str,
        evidence_data: dict,
    ) -> dict:
        """Report collected evidence to Master."""
        return await self._request(
            "POST",
            f"/api/v1/cloud-relay/tasks/{task_id}/evidence",
            data={
                "tenant_id": self.config.tenant_id,
                "execution_id": execution_id,
                "evidence_type": evidence_type,
                "evidence_data": evidence_data,
            },
        )

    # ==========================================================================
    # WAF Testing API
    # ==========================================================================

    async def submit_waf_test(
        self,
        target_domain: str,
        test_category: str,
        payloads: list[dict],
    ) -> dict:
        """Submit WAF test for execution."""
        return await self._request(
            "POST",
            "/api/v1/cloud-relay/waf-test",
            data={
                "tenant_id": self.config.tenant_id,
                "target_domain": target_domain,
                "test_category": test_category,
                "payloads": payloads,
            },
        )

    async def get_waf_test_result(self, test_id: str) -> dict:
        """Get WAF test results."""
        return await self._request(
            "GET",
            f"/api/v1/cloud-relay/waf-test/{test_id}",
            params={"tenant_id": self.config.tenant_id},
        )

    # ==========================================================================
    # C2 Channel API
    # ==========================================================================

    async def register_c2_channel(
        self,
        channel_type: str,
        endpoint: str,
        metadata: Optional[dict] = None,
    ) -> dict:
        """Register a C2 channel with Master."""
        return await self._request(
            "POST",
            "/api/v1/cloud-relay/c2/channels",
            data={
                "tenant_id": self.config.tenant_id,
                "channel_type": channel_type,
                "endpoint": endpoint,
                "metadata": metadata or {},
            },
        )

    async def report_c2_callback(
        self,
        channel_id: str,
        callback_data: dict,
    ) -> dict:
        """Report C2 callback received."""
        return await self._request(
            "POST",
            f"/api/v1/cloud-relay/c2/channels/{channel_id}/callback",
            data={
                "tenant_id": self.config.tenant_id,
                "callback_data": callback_data,
            },
        )
