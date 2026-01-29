"""
Mirqab Cloud Relay — Load Tests (Locust)

Usage:
    # Web UI (http://localhost:8089)
    locust -f tests/load/locustfile.py --host=http://localhost:8100

    # Headless CLI
    locust -f tests/load/locustfile.py --host=http://localhost:8100 \
        --headless -u 50 -r 10 --run-time 60s --html=tests/load/report.html

Environment variables:
    API_KEY    — API key for authenticated endpoints (default: cloud-relay-test-api-key-2026)
    TENANT_ID  — Tenant ID header value (default: test-tenant)
"""

import os
import uuid

from locust import HttpUser, between, tag, task


API_KEY = os.environ.get("API_KEY", "cloud-relay-test-api-key-2026")
TENANT_ID = os.environ.get("TENANT_ID", "test-tenant")


class HealthUser(HttpUser):
    """Baseline: unauthenticated health endpoint only."""

    wait_time = between(0.1, 0.5)
    weight = 1

    @tag("health")
    @task
    def health(self):
        self.client.get("/health")

    @tag("health")
    @task
    def healthz(self):
        self.client.get("/healthz")


class AuthenticatedUser(HttpUser):
    """Authenticated endpoints — API info, quota, task CRUD."""

    wait_time = between(0.5, 2)
    weight = 3

    def on_start(self):
        self.headers = {"X-API-Key": API_KEY, "X-Tenant-ID": TENANT_ID}

    @tag("auth", "read")
    @task(3)
    def api_info(self):
        self.client.get("/api/v1", headers=self.headers)

    @tag("auth", "read")
    @task(2)
    def quota(self):
        self.client.get("/api/v1/quota", headers=self.headers)

    @tag("auth", "write")
    @task(1)
    def create_task(self):
        self.client.post(
            "/api/v1/tasks",
            headers=self.headers,
            json={
                "task_type": "waf",
                "parameters": {"target": "http://example.com", "test_id": str(uuid.uuid4())},
            },
        )

    @tag("auth", "read")
    @task(1)
    def get_task_status(self):
        # Use a dummy task_id — expect 404, measures middleware + routing latency
        self.client.get(
            "/api/v1/tasks/00000000-0000-0000-0000-000000000000",
            headers=self.headers,
            name="/api/v1/tasks/[id]",
        )


class RateLimitUser(HttpUser):
    """Rapid-fire requests to stress rate limiting. Expects 429 responses."""

    wait_time = between(0, 0.05)
    weight = 1

    def on_start(self):
        self.headers = {"X-API-Key": API_KEY, "X-Tenant-ID": TENANT_ID}

    @tag("ratelimit")
    @task
    def burst(self):
        with self.client.get(
            "/api/v1", headers=self.headers, catch_response=True
        ) as resp:
            # 429 is expected under load — don't count as failure
            if resp.status_code == 429:
                resp.success()


class RealisticUser(HttpUser):
    """Weighted mix simulating real-world traffic patterns."""

    wait_time = between(1, 3)
    weight = 5

    def on_start(self):
        self.headers = {"X-API-Key": API_KEY, "X-Tenant-ID": TENANT_ID}

    @tag("realistic")
    @task(40)
    def health(self):
        self.client.get("/health")

    @tag("realistic")
    @task(30)
    def api_info(self):
        self.client.get("/api/v1", headers=self.headers)

    @tag("realistic")
    @task(20)
    def quota(self):
        self.client.get("/api/v1/quota", headers=self.headers)

    @tag("realistic")
    @task(10)
    def create_task(self):
        self.client.post(
            "/api/v1/tasks",
            headers=self.headers,
            json={
                "task_type": "c2_http",
                "parameters": {"callback_interval": 30},
            },
        )
