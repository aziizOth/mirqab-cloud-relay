"""
Cloud Relay API Gateway - Prometheus Metrics

Custom metrics for monitoring gateway health, tenant activity, and backend performance.
"""
from __future__ import annotations

from prometheus_client import Counter, Gauge, Histogram, Info

# Request metrics
REQUEST_COUNT = Counter(
    "gateway_requests_total",
    "Total API Gateway requests",
    ["method", "path", "status", "tenant_id"],
)

REQUEST_DURATION = Histogram(
    "gateway_request_duration_seconds",
    "Request duration in seconds",
    ["method", "path", "tenant_id"],
    buckets=(0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0),
)

ACTIVE_REQUESTS = Gauge(
    "gateway_active_requests",
    "Currently in-flight requests",
    ["tenant_id"],
)

# Auth metrics
AUTH_FAILURES = Counter(
    "gateway_auth_failures_total",
    "Authentication/authorization failures",
    ["reason"],
)

# Rate limiting
RATE_LIMIT_HITS = Counter(
    "gateway_rate_limit_hits_total",
    "Rate limit exceeded events",
    ["tenant_id"],
)

# Quota
QUOTA_EXCEEDED = Counter(
    "gateway_quota_exceeded_total",
    "Quota exceeded events",
    ["tenant_id", "feature"],
)

# Backend proxy
PROXY_ERRORS = Counter(
    "gateway_proxy_errors_total",
    "Backend proxy errors",
    ["backend", "error_type"],
)

PROXY_DURATION = Histogram(
    "gateway_proxy_duration_seconds",
    "Backend proxy request duration",
    ["backend"],
    buckets=(0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0),
)

# Service info
GATEWAY_INFO = Info(
    "gateway",
    "API Gateway build information",
)
GATEWAY_INFO.info({
    "version": "1.0.0",
    "service": "cloud-relay-api-gateway",
})
