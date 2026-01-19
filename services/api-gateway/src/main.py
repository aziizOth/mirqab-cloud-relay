"""
Cloud Relay API Gateway
Central routing and authentication for all Cloud Relay services.
"""

import os
import ssl
import asyncio
from contextlib import asynccontextmanager

import structlog
import uvicorn
from fastapi import FastAPI, Request, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from prometheus_client import make_asgi_app, Counter, Histogram
import httpx

# Configure structured logging
structlog.configure(
    processors=[
        structlog.stdlib.filter_by_level,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.JSONRenderer()
    ],
    wrapper_class=structlog.stdlib.BoundLogger,
    context_class=dict,
    logger_factory=structlog.stdlib.LoggerFactory(),
)

logger = structlog.get_logger(__name__)

# Metrics
REQUEST_COUNT = Counter(
    'api_gateway_requests_total',
    'Total API Gateway requests',
    ['service', 'method', 'status']
)
REQUEST_LATENCY = Histogram(
    'api_gateway_request_latency_seconds',
    'API Gateway request latency',
    ['service']
)

# Service registry
SERVICES = {
    'c2': os.getenv('C2_SERVICE', 'cloud-relay-c2:443'),
    'exfil': os.getenv('EXFIL_SERVICE', 'cloud-relay-exfil:443'),
    'phishing': os.getenv('PHISHING_SERVICE', 'cloud-relay-phishing:443'),
    'payload': os.getenv('PAYLOAD_SERVICE', 'cloud-relay-payload:443'),
    'waf': os.getenv('WAF_SERVICE', 'cloud-relay-waf:443'),
}


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan handler."""
    logger.info("api_gateway_starting", services=list(SERVICES.keys()))

    # Initialize HTTP client for proxying
    app.state.http_client = httpx.AsyncClient(
        verify=False,  # Internal services use self-signed certs
        timeout=30.0,
        limits=httpx.Limits(max_connections=100, max_keepalive_connections=20)
    )

    yield

    # Cleanup
    await app.state.http_client.aclose()
    logger.info("api_gateway_stopped")


app = FastAPI(
    title="Cloud Relay API Gateway",
    description="Central gateway for Cloud Relay adversary simulation services",
    version="1.0.0",
    lifespan=lifespan,
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configured per environment
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount Prometheus metrics
metrics_app = make_asgi_app()
app.mount("/metrics", metrics_app)


@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {"status": "healthy", "service": "api-gateway"}


@app.get("/ready")
async def readiness_check():
    """Readiness check - verify all backend services are reachable."""
    services_status = {}
    all_ready = True

    for name, endpoint in SERVICES.items():
        try:
            response = await app.state.http_client.get(
                f"https://{endpoint}/health",
                timeout=5.0
            )
            services_status[name] = response.status_code == 200
        except Exception as e:
            services_status[name] = False
            all_ready = False
            logger.warning("service_unreachable", service=name, error=str(e))

    if not all_ready:
        return JSONResponse(
            status_code=503,
            content={"status": "degraded", "services": services_status}
        )

    return {"status": "ready", "services": services_status}


@app.api_route("/api/v1/{service}/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
async def proxy_request(service: str, path: str, request: Request):
    """
    Proxy requests to backend services.

    Routes:
    - /api/v1/c2/* -> C2 Simulator
    - /api/v1/exfil/* -> Exfil Server
    - /api/v1/phishing/* -> Phishing Server
    - /api/v1/payload/* -> Payload Hosting
    - /api/v1/waf/* -> WAF Tester
    """
    if service not in SERVICES:
        raise HTTPException(status_code=404, detail=f"Unknown service: {service}")

    endpoint = SERVICES[service]
    target_url = f"https://{endpoint}/{path}"

    # Get request body
    body = await request.body()

    # Forward headers (excluding hop-by-hop)
    headers = {
        k: v for k, v in request.headers.items()
        if k.lower() not in ('host', 'connection', 'transfer-encoding')
    }
    headers['X-Forwarded-For'] = request.client.host
    headers['X-Forwarded-Proto'] = 'https'

    with REQUEST_LATENCY.labels(service=service).time():
        try:
            response = await app.state.http_client.request(
                method=request.method,
                url=target_url,
                headers=headers,
                content=body,
                params=request.query_params,
            )

            REQUEST_COUNT.labels(
                service=service,
                method=request.method,
                status=response.status_code
            ).inc()

            return JSONResponse(
                content=response.json() if response.headers.get('content-type', '').startswith('application/json') else response.text,
                status_code=response.status_code,
                headers={k: v for k, v in response.headers.items() if k.lower() not in ('content-encoding', 'transfer-encoding', 'content-length')}
            )

        except httpx.TimeoutException:
            REQUEST_COUNT.labels(service=service, method=request.method, status=504).inc()
            raise HTTPException(status_code=504, detail="Gateway timeout")
        except httpx.ConnectError:
            REQUEST_COUNT.labels(service=service, method=request.method, status=502).inc()
            raise HTTPException(status_code=502, detail="Service unavailable")


@app.get("/api/v1/services")
async def list_services():
    """List available services."""
    return {
        "services": list(SERVICES.keys()),
        "environment": os.getenv("ENVIRONMENT", "development"),
        "domain": os.getenv("DOMAIN", "localhost"),
    }


if __name__ == "__main__":
    # SSL configuration
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
        workers=int(os.getenv("WORKERS", "4")),
    )
