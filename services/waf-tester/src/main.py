"""
Cloud Relay WAF Tester
Tests Web Application Firewall effectiveness with OWASP payloads.
Provides bypass testing and effectiveness scoring.
"""

import os
import ssl
import uuid
import asyncio
from datetime import datetime
from typing import Optional, Dict, List
from contextlib import asynccontextmanager
from enum import Enum

import structlog
import uvicorn
from fastapi import FastAPI, Request, HTTPException, BackgroundTasks
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from prometheus_client import make_asgi_app, Counter, Gauge, Histogram
import redis.asyncio as redis
import httpx
import aiofiles

structlog.configure(
    processors=[
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.JSONRenderer()
    ],
    wrapper_class=structlog.stdlib.BoundLogger,
    context_class=dict,
    logger_factory=structlog.stdlib.LoggerFactory(),
)

logger = structlog.get_logger(__name__)

# Metrics
TEST_COUNT = Counter('waf_tests_total', 'Total WAF tests', ['category', 'result'])
BYPASS_COUNT = Counter('waf_bypasses_total', 'Total WAF bypasses detected', ['category'])
ACTIVE_SCANS = Gauge('waf_active_scans', 'Active WAF scans')
TEST_LATENCY = Histogram('waf_test_latency_seconds', 'Test execution latency')


class TestCategory(str, Enum):
    SQLI = "sqli"
    XSS = "xss"
    RCE = "rce"
    LFI = "lfi"
    SSRF = "ssrf"
    XXE = "xxe"
    SSTI = "ssti"
    IDOR = "idor"
    CSRF = "csrf"


class TestResult(str, Enum):
    BLOCKED = "blocked"
    BYPASSED = "bypassed"
    ERROR = "error"
    TIMEOUT = "timeout"


class WafTest(BaseModel):
    """Single WAF test case."""
    test_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    category: TestCategory
    payload: str
    description: Optional[str] = None
    encoding: Optional[str] = None  # url, base64, unicode, etc.


class ScanConfig(BaseModel):
    """WAF scan configuration."""
    scan_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    target_url: str
    categories: List[TestCategory] = [c for c in TestCategory]
    rate_limit: int = 10  # requests per second
    timeout: int = 10
    custom_headers: Dict[str, str] = {}
    follow_redirects: bool = False


class ScanResult(BaseModel):
    """WAF scan results."""
    scan_id: str
    target_url: str
    started_at: datetime
    completed_at: Optional[datetime] = None
    status: str = "running"
    total_tests: int = 0
    blocked: int = 0
    bypassed: int = 0
    errors: int = 0
    timeouts: int = 0
    effectiveness_score: float = 0.0
    results: List[Dict] = []


# Payload storage
PAYLOAD_DIR = "/app/payloads"
payloads: Dict[TestCategory, List[str]] = {}
scans: Dict[str, ScanResult] = {}


async def load_payloads():
    """Load test payloads from files."""
    for category in TestCategory:
        payload_file = f"{PAYLOAD_DIR}/{category.value}.txt"
        if os.path.exists(payload_file):
            async with aiofiles.open(payload_file, 'r') as f:
                content = await f.read()
                payloads[category] = [
                    line.strip() for line in content.split('\n')
                    if line.strip() and not line.startswith('#')
                ]
        else:
            payloads[category] = get_default_payloads(category)

    logger.info(
        "payloads_loaded",
        categories={c.value: len(p) for c, p in payloads.items()}
    )


def get_default_payloads(category: TestCategory) -> List[str]:
    """Get default payloads for a category."""
    defaults = {
        TestCategory.SQLI: [
            "' OR '1'='1",
            "' OR '1'='1'--",
            "1' ORDER BY 1--+",
            "1' UNION SELECT NULL--+",
            "admin'--",
        ],
        TestCategory.XSS: [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "javascript:alert('XSS')",
        ],
        TestCategory.RCE: [
            "; ls -la",
            "| cat /etc/passwd",
            "`whoami`",
            "$(id)",
        ],
        TestCategory.LFI: [
            "../../../etc/passwd",
            "....//....//....//etc/passwd",
            "/etc/passwd%00",
        ],
        TestCategory.SSRF: [
            "http://localhost/admin",
            "http://127.0.0.1/admin",
            "http://169.254.169.254/latest/meta-data/",
        ],
        TestCategory.XXE: [
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
        ],
        TestCategory.SSTI: [
            "{{7*7}}",
            "${7*7}",
            "<%= 7*7 %>",
        ],
        TestCategory.IDOR: [
            "../user/1",
            "user_id=1",
        ],
        TestCategory.CSRF: [
            # CSRF payloads are more about missing tokens
        ],
    }
    return defaults.get(category, [])


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan."""
    logger.info("waf_tester_starting")

    redis_host = os.getenv("REDIS_HOST", "localhost")
    redis_port = int(os.getenv("REDIS_PORT", "6379"))
    app.state.redis = await redis.from_url(
        f"redis://{redis_host}:{redis_port}",
        encoding="utf-8",
        decode_responses=True
    )

    # Load payloads
    await load_payloads()

    yield

    await app.state.redis.close()
    logger.info("waf_tester_stopped")


app = FastAPI(
    title="Cloud Relay WAF Tester",
    description="WAF effectiveness testing service",
    version="1.0.0",
    lifespan=lifespan,
)

metrics_app = make_asgi_app()
app.mount("/metrics", metrics_app)


@app.get("/health")
async def health():
    return {"status": "healthy", "service": "waf-tester"}


@app.get("/ready")
async def ready():
    try:
        await app.state.redis.ping()
        return {"status": "ready"}
    except Exception:
        return JSONResponse(status_code=503, content={"status": "not ready"})


async def test_payload(
    client: httpx.AsyncClient,
    url: str,
    payload: str,
    category: TestCategory,
    headers: Dict[str, str],
    timeout: int,
) -> Dict:
    """Test a single payload against the target."""
    result = {
        "payload": payload,
        "category": category.value,
        "result": TestResult.ERROR.value,
        "status_code": None,
        "response_length": None,
        "latency_ms": None,
    }

    start_time = datetime.utcnow()

    try:
        # Test in different injection points
        test_url = f"{url}?q={payload}"

        with TEST_LATENCY.time():
            response = await client.get(
                test_url,
                headers=headers,
                timeout=timeout,
            )

        latency = (datetime.utcnow() - start_time).total_seconds() * 1000
        result["latency_ms"] = latency
        result["status_code"] = response.status_code
        result["response_length"] = len(response.content)

        # Determine if blocked or bypassed
        if response.status_code in (403, 406, 429, 503):
            result["result"] = TestResult.BLOCKED.value
            TEST_COUNT.labels(category=category.value, result="blocked").inc()
        elif response.status_code == 200:
            # Check response content for WAF block messages
            content = response.text.lower()
            block_indicators = [
                "blocked", "forbidden", "security", "firewall",
                "access denied", "not allowed", "detected"
            ]
            if any(indicator in content for indicator in block_indicators):
                result["result"] = TestResult.BLOCKED.value
                TEST_COUNT.labels(category=category.value, result="blocked").inc()
            else:
                result["result"] = TestResult.BYPASSED.value
                TEST_COUNT.labels(category=category.value, result="bypassed").inc()
                BYPASS_COUNT.labels(category=category.value).inc()
        else:
            result["result"] = TestResult.BYPASSED.value
            TEST_COUNT.labels(category=category.value, result="bypassed").inc()

    except httpx.TimeoutException:
        result["result"] = TestResult.TIMEOUT.value
        TEST_COUNT.labels(category=category.value, result="timeout").inc()
    except Exception as e:
        result["error"] = str(e)
        TEST_COUNT.labels(category=category.value, result="error").inc()

    return result


async def run_scan(scan_config: ScanConfig):
    """Run a WAF scan."""
    scan = ScanResult(
        scan_id=scan_config.scan_id,
        target_url=scan_config.target_url,
        started_at=datetime.utcnow(),
    )
    scans[scan.scan_id] = scan
    ACTIVE_SCANS.set(len([s for s in scans.values() if s.status == "running"]))

    logger.info(
        "scan_started",
        scan_id=scan.scan_id,
        target=scan_config.target_url,
        categories=[c.value for c in scan_config.categories],
    )

    async with httpx.AsyncClient(verify=False, follow_redirects=scan_config.follow_redirects) as client:
        for category in scan_config.categories:
            category_payloads = payloads.get(category, [])

            for payload in category_payloads:
                scan.total_tests += 1

                result = await test_payload(
                    client=client,
                    url=scan_config.target_url,
                    payload=payload,
                    category=category,
                    headers=scan_config.custom_headers,
                    timeout=scan_config.timeout,
                )
                scan.results.append(result)

                # Update counts
                if result["result"] == TestResult.BLOCKED.value:
                    scan.blocked += 1
                elif result["result"] == TestResult.BYPASSED.value:
                    scan.bypassed += 1
                elif result["result"] == TestResult.TIMEOUT.value:
                    scan.timeouts += 1
                else:
                    scan.errors += 1

                # Rate limiting
                await asyncio.sleep(1 / scan_config.rate_limit)

    # Calculate effectiveness
    if scan.total_tests > 0:
        scan.effectiveness_score = (scan.blocked / scan.total_tests) * 100

    scan.completed_at = datetime.utcnow()
    scan.status = "completed"
    ACTIVE_SCANS.set(len([s for s in scans.values() if s.status == "running"]))

    logger.info(
        "scan_completed",
        scan_id=scan.scan_id,
        total_tests=scan.total_tests,
        blocked=scan.blocked,
        bypassed=scan.bypassed,
        effectiveness=f"{scan.effectiveness_score:.1f}%",
    )


# API Endpoints
@app.post("/api/scan")
async def start_scan(config: ScanConfig, background_tasks: BackgroundTasks):
    """Start a WAF scan."""
    background_tasks.add_task(run_scan, config)

    return {
        "scan_id": config.scan_id,
        "status": "started",
        "target": config.target_url,
        "categories": [c.value for c in config.categories],
    }


@app.get("/api/scan/{scan_id}")
async def get_scan(scan_id: str):
    """Get scan results."""
    if scan_id not in scans:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scans[scan_id]


@app.get("/api/scans")
async def list_scans():
    """List all scans."""
    return {"scans": list(scans.values())}


@app.get("/api/payloads")
async def get_payloads(category: Optional[TestCategory] = None):
    """Get available test payloads."""
    if category:
        return {category.value: payloads.get(category, [])}
    return {c.value: p for c, p in payloads.items()}


@app.post("/api/test/single")
async def test_single(
    target_url: str,
    payload: str,
    category: TestCategory = TestCategory.XSS,
):
    """Test a single payload."""
    async with httpx.AsyncClient(verify=False) as client:
        result = await test_payload(
            client=client,
            url=target_url,
            payload=payload,
            category=category,
            headers={},
            timeout=10,
        )
    return result


# Quick test endpoint for common attacks
@app.get("/api/quicktest")
async def quick_test(target_url: str):
    """Quick test with common payloads."""
    quick_payloads = [
        (TestCategory.SQLI, "' OR '1'='1"),
        (TestCategory.XSS, "<script>alert(1)</script>"),
        (TestCategory.RCE, "; cat /etc/passwd"),
        (TestCategory.LFI, "../../../etc/passwd"),
    ]

    results = []
    async with httpx.AsyncClient(verify=False) as client:
        for category, payload in quick_payloads:
            result = await test_payload(
                client=client,
                url=target_url,
                payload=payload,
                category=category,
                headers={},
                timeout=10,
            )
            results.append(result)

    blocked = sum(1 for r in results if r["result"] == "blocked")
    return {
        "target": target_url,
        "tests": len(results),
        "blocked": blocked,
        "bypassed": len(results) - blocked,
        "effectiveness": f"{(blocked / len(results) * 100):.0f}%",
        "results": results,
    }


if __name__ == "__main__":
    ssl_context = None
    cert_file = "/app/certs/tls.crt"
    key_file = "/app/certs/tls.key"

    if os.path.exists(cert_file) and os.path.exists(key_file):
        ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ssl_context.load_cert_chain(cert_file, key_file)

    uvicorn.run(
        "src.main:app",
        host="0.0.0.0",
        port=8443,
        ssl_keyfile=key_file if ssl_context else None,
        ssl_certfile=cert_file if ssl_context else None,
        log_level=os.getenv("LOG_LEVEL", "info").lower(),
    )
