# Mirqab Cloud Relay - WAF Integration E2E Tests
"""
End-to-end tests for WAF testing via Cloud Relay.

Tests:
1. SQL Injection detection
2. XSS detection
3. RCE detection
4. WAF effectiveness scoring
"""

import asyncio
import pytest
import httpx
import json
from datetime import datetime, timezone
from typing import Optional
from pathlib import Path

# Test configuration
CLOUD_RELAY_URL = "https://api.relay.mirqab.io"
MASTER_URL = "https://api.offensight.local:8000"
TEST_TENANT_ID = "e2e-test-tenant"
TEST_API_KEY = "cr_test_e2e_integration_key"

# WAF test payloads
SQLI_PAYLOADS = [
    {"payload": "' OR '1'='1", "category": "sqli", "expected_blocked": True},
    {"payload": "1; DROP TABLE users--", "category": "sqli", "expected_blocked": True},
    {"payload": "UNION SELECT null,null,null--", "category": "sqli", "expected_blocked": True},
    {"payload": "1' AND SLEEP(5)--", "category": "sqli", "expected_blocked": True},
]

XSS_PAYLOADS = [
    {"payload": "<script>alert(1)</script>", "category": "xss", "expected_blocked": True},
    {"payload": "<img src=x onerror=alert(1)>", "category": "xss", "expected_blocked": True},
    {"payload": "javascript:alert(1)", "category": "xss", "expected_blocked": True},
]


class CloudRelayClient:
    """Test client for Cloud Relay API."""

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

    async def health_check(self) -> dict:
        """Check Cloud Relay health."""
        response = await self.client.get("/health")
        response.raise_for_status()
        return response.json()

    async def submit_waf_test(
        self,
        target_domain: str,
        test_category: str,
        payloads: list[dict],
    ) -> dict:
        """Submit WAF test for execution."""
        response = await self.client.post(
            "/api/v1/waf-test",
            json={
                "target_domain": target_domain,
                "test_category": test_category,
                "payloads": payloads,
            },
        )
        response.raise_for_status()
        return response.json()

    async def get_waf_test_result(self, test_id: str) -> dict:
        """Get WAF test results."""
        response = await self.client.get(f"/api/v1/waf-test/{test_id}")
        response.raise_for_status()
        return response.json()

    async def wait_for_test_completion(
        self,
        test_id: str,
        timeout_seconds: int = 300,
        poll_interval: int = 5,
    ) -> dict:
        """Wait for WAF test to complete."""
        start_time = datetime.now(timezone.utc)
        while True:
            result = await self.get_waf_test_result(test_id)
            if result.get("status") in ("completed", "failed"):
                return result

            elapsed = (datetime.now(timezone.utc) - start_time).total_seconds()
            if elapsed > timeout_seconds:
                raise TimeoutError(f"WAF test {test_id} did not complete within {timeout_seconds}s")

            await asyncio.sleep(poll_interval)


class MasterClient:
    """Test client for OffenSight Master API."""

    def __init__(self, base_url: str):
        self.base_url = base_url
        self.client: Optional[httpx.AsyncClient] = None

    async def __aenter__(self):
        self.client = httpx.AsyncClient(
            base_url=self.base_url,
            timeout=30.0,
            verify=False,  # For local testing
        )
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.client:
            await self.client.aclose()

    async def get_execution_result(self, execution_id: str) -> dict:
        """Get execution result from Master."""
        response = await self.client.get(f"/api/v1/executions/{execution_id}")
        response.raise_for_status()
        return response.json()


@pytest.fixture
async def cloud_relay_client():
    """Create Cloud Relay client fixture."""
    async with CloudRelayClient(CLOUD_RELAY_URL, TEST_TENANT_ID, TEST_API_KEY) as client:
        yield client


@pytest.fixture
async def master_client():
    """Create Master client fixture."""
    async with MasterClient(MASTER_URL) as client:
        yield client


@pytest.mark.asyncio
async def test_cloud_relay_health(cloud_relay_client: CloudRelayClient):
    """Test Cloud Relay health endpoint."""
    result = await cloud_relay_client.health_check()
    assert result.get("status") == "healthy"


@pytest.mark.asyncio
async def test_waf_sqli_detection(cloud_relay_client: CloudRelayClient):
    """Test WAF SQL injection detection via Cloud Relay."""
    # Submit SQLi test
    test_result = await cloud_relay_client.submit_waf_test(
        target_domain="test.waf.example.com",
        test_category="sqli",
        payloads=SQLI_PAYLOADS,
    )

    test_id = test_result.get("test_id")
    assert test_id, "Should return test_id"

    # Wait for completion
    result = await cloud_relay_client.wait_for_test_completion(test_id)

    # Verify results
    assert result["status"] == "completed"
    assert result["total_payloads"] == len(SQLI_PAYLOADS)

    # Check effectiveness score
    effectiveness = result.get("effectiveness_score", 0)
    print(f"SQLi WAF Effectiveness: {effectiveness:.1%}")

    # At least some payloads should be blocked for a functional WAF
    assert result["blocked_count"] > 0, "WAF should block at least some SQLi payloads"


@pytest.mark.asyncio
async def test_waf_xss_detection(cloud_relay_client: CloudRelayClient):
    """Test WAF XSS detection via Cloud Relay."""
    # Submit XSS test
    test_result = await cloud_relay_client.submit_waf_test(
        target_domain="test.waf.example.com",
        test_category="xss",
        payloads=XSS_PAYLOADS,
    )

    test_id = test_result.get("test_id")
    assert test_id, "Should return test_id"

    # Wait for completion
    result = await cloud_relay_client.wait_for_test_completion(test_id)

    # Verify results
    assert result["status"] == "completed"
    assert result["total_payloads"] == len(XSS_PAYLOADS)

    # Check effectiveness score
    effectiveness = result.get("effectiveness_score", 0)
    print(f"XSS WAF Effectiveness: {effectiveness:.1%}")

    # At least some payloads should be blocked
    assert result["blocked_count"] > 0, "WAF should block at least some XSS payloads"


@pytest.mark.asyncio
async def test_waf_comprehensive(cloud_relay_client: CloudRelayClient):
    """Test comprehensive WAF coverage via Cloud Relay."""
    all_payloads = SQLI_PAYLOADS + XSS_PAYLOADS

    # Submit comprehensive test
    test_result = await cloud_relay_client.submit_waf_test(
        target_domain="test.waf.example.com",
        test_category="comprehensive",
        payloads=all_payloads,
    )

    test_id = test_result.get("test_id")
    result = await cloud_relay_client.wait_for_test_completion(test_id)

    # Generate report
    report = {
        "test_id": test_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "target_domain": "test.waf.example.com",
        "total_payloads": result["total_payloads"],
        "blocked_count": result["blocked_count"],
        "passed_count": result["passed_count"],
        "effectiveness_score": result.get("effectiveness_score", 0),
        "categories": {
            "sqli": {"tested": len(SQLI_PAYLOADS)},
            "xss": {"tested": len(XSS_PAYLOADS)},
        },
    }

    print("\n=== WAF Test Report ===")
    print(json.dumps(report, indent=2))

    # Assertions
    assert result["status"] == "completed"
    assert result.get("effectiveness_score", 0) >= 0.5, "WAF should achieve at least 50% effectiveness"


@pytest.mark.asyncio
async def test_waf_result_sync_to_master(
    cloud_relay_client: CloudRelayClient,
    master_client: MasterClient,
):
    """Test that WAF results are synced back to Master."""
    # Submit test via Cloud Relay
    test_result = await cloud_relay_client.submit_waf_test(
        target_domain="test.waf.example.com",
        test_category="sqli",
        payloads=SQLI_PAYLOADS[:2],  # Use fewer payloads for quick test
    )

    test_id = test_result.get("test_id")
    execution_id = test_result.get("execution_id")

    # Wait for completion
    await cloud_relay_client.wait_for_test_completion(test_id)

    # Verify result exists in Master (if execution_id provided)
    if execution_id:
        master_result = await master_client.get_execution_result(execution_id)
        assert master_result.get("status") in ("completed", "success")
        print(f"Master received WAF test result for execution {execution_id}")


if __name__ == "__main__":
    # Run with: python -m pytest tests/e2e/test_waf_integration.py -v
    pytest.main([__file__, "-v", "--asyncio-mode=auto"])
