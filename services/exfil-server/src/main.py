"""
Cloud Relay Exfil Server
Simulates data exfiltration channels for adversary emulation.
Supports HTTP, DNS tunneling, and more.
"""

import os
import ssl
import uuid
import base64
import hashlib
import asyncio
from datetime import datetime, timezone
from typing import Optional, Dict, List
from contextlib import asynccontextmanager
from enum import Enum

import structlog
import uvicorn
from fastapi import FastAPI, Request, HTTPException, UploadFile, File, Form
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel, Field
from prometheus_client import make_asgi_app, Counter, Gauge, Histogram
import redis.asyncio as redis
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
EXFIL_BYTES = Counter('exfil_bytes_total', 'Total bytes exfiltrated', ['channel'])
EXFIL_REQUESTS = Counter('exfil_requests_total', 'Total exfil requests', ['channel', 'status'])
EXFIL_SESSIONS = Gauge('exfil_active_sessions', 'Active exfil sessions')
CHUNK_LATENCY = Histogram('exfil_chunk_latency_seconds', 'Chunk processing latency')


class ExfilChannel(str, Enum):
    HTTP_POST = "http_post"
    HTTP_CHUNKED = "http_chunked"
    DNS_TXT = "dns_txt"
    DNS_CNAME = "dns_cname"
    ICMP = "icmp"
    WEBSOCKET = "websocket"


class ExfilSession(BaseModel):
    """Exfiltration session for multi-chunk transfers."""
    session_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    channel: ExfilChannel
    source_ip: str
    filename: Optional[str] = None
    total_size: Optional[int] = None
    received_chunks: int = 0
    total_chunks: Optional[int] = None
    started_at: datetime = Field(default_factory=datetime.utcnow)
    last_activity: datetime = Field(default_factory=datetime.utcnow)
    completed: bool = False
    checksum: Optional[str] = None


class ChunkData(BaseModel):
    """Data chunk for chunked exfiltration."""
    session_id: str
    chunk_index: int
    data: str  # Base64 encoded
    is_last: bool = False


# Session storage
sessions: Dict[str, ExfilSession] = {}
session_data: Dict[str, bytes] = {}


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan."""
    logger.info("exfil_server_starting")

    redis_host = os.getenv("REDIS_HOST", "localhost")
    redis_port = int(os.getenv("REDIS_PORT", "6379"))
    app.state.redis = await redis.from_url(
        f"redis://{redis_host}:{redis_port}",
        encoding="utf-8",
        decode_responses=True
    )

    # Create data directory
    os.makedirs("/app/data/exfil", exist_ok=True)

    yield

    await app.state.redis.close()
    logger.info("exfil_server_stopped")


app = FastAPI(
    title="Cloud Relay Exfil Server",
    description="Data exfiltration simulation for adversary emulation",
    version="1.0.0",
    lifespan=lifespan,
)

metrics_app = make_asgi_app()
app.mount("/metrics", metrics_app)


@app.get("/health")
async def health():
    return {"status": "healthy", "service": "exfil-server"}


@app.get("/ready")
async def ready():
    try:
        await app.state.redis.ping()
        return {"status": "ready"}
    except Exception:
        return JSONResponse(status_code=503, content={"status": "not ready"})


# HTTP POST exfiltration
@app.post("/upload")
@app.post("/api/data")
@app.post("/submit")
async def http_post_exfil(
    request: Request,
    file: Optional[UploadFile] = File(None),
    data: Optional[str] = Form(None),
):
    """
    HTTP POST exfiltration endpoint.
    Accepts file uploads or base64 encoded data.
    """
    client_ip = request.client.host
    channel = ExfilChannel.HTTP_POST

    try:
        if file:
            content = await file.read()
            filename = file.filename
        elif data:
            content = base64.b64decode(data)
            filename = f"data_{uuid.uuid4().hex[:8]}.bin"
        else:
            # Raw body
            content = await request.body()
            filename = f"raw_{uuid.uuid4().hex[:8]}.bin"

        # Save file
        file_path = f"/app/data/exfil/{filename}"
        async with aiofiles.open(file_path, 'wb') as f:
            await f.write(content)

        # Calculate checksum
        checksum = hashlib.sha256(content).hexdigest()

        # Create session record
        session = ExfilSession(
            channel=channel,
            source_ip=client_ip,
            filename=filename,
            total_size=len(content),
            completed=True,
            checksum=checksum,
        )
        sessions[session.session_id] = session

        # Update metrics
        EXFIL_BYTES.labels(channel=channel.value).inc(len(content))
        EXFIL_REQUESTS.labels(channel=channel.value, status="success").inc()

        logger.info(
            "exfil_received",
            session_id=session.session_id,
            channel=channel.value,
            size=len(content),
            filename=filename,
            source_ip=client_ip,
        )

        return {
            "status": "success",
            "session_id": session.session_id,
            "size": len(content),
            "checksum": checksum,
        }

    except Exception as e:
        EXFIL_REQUESTS.labels(channel=channel.value, status="error").inc()
        logger.error("exfil_error", error=str(e), source_ip=client_ip)
        raise HTTPException(status_code=500, detail=str(e))


# Chunked exfiltration for large files
@app.post("/chunk/start")
async def start_chunked_exfil(
    request: Request,
    filename: str = Form(...),
    total_size: int = Form(...),
    total_chunks: int = Form(...),
):
    """Start a chunked exfiltration session."""
    client_ip = request.client.host

    session = ExfilSession(
        channel=ExfilChannel.HTTP_CHUNKED,
        source_ip=client_ip,
        filename=filename,
        total_size=total_size,
        total_chunks=total_chunks,
    )
    sessions[session.session_id] = session
    session_data[session.session_id] = b""

    EXFIL_SESSIONS.set(len([s for s in sessions.values() if not s.completed]))

    logger.info(
        "chunked_exfil_started",
        session_id=session.session_id,
        filename=filename,
        total_size=total_size,
        total_chunks=total_chunks,
    )

    return {"session_id": session.session_id, "status": "ready"}


@app.post("/chunk/upload")
async def upload_chunk(chunk: ChunkData):
    """Upload a data chunk."""
    with CHUNK_LATENCY.time():
        if chunk.session_id not in sessions:
            raise HTTPException(status_code=404, detail="Session not found")

        session = sessions[chunk.session_id]
        if session.completed:
            raise HTTPException(status_code=400, detail="Session already completed")

        # Decode and append data
        data = base64.b64decode(chunk.data)
        session_data[chunk.session_id] += data
        session.received_chunks += 1
        session.last_activity = datetime.now(timezone.utc)

        EXFIL_BYTES.labels(channel=ExfilChannel.HTTP_CHUNKED.value).inc(len(data))

        if chunk.is_last:
            # Save complete file
            complete_data = session_data[chunk.session_id]
            file_path = f"/app/data/exfil/{session.filename}"

            async with aiofiles.open(file_path, 'wb') as f:
                await f.write(complete_data)

            session.completed = True
            session.checksum = hashlib.sha256(complete_data).hexdigest()

            # Cleanup
            del session_data[chunk.session_id]
            EXFIL_SESSIONS.set(len([s for s in sessions.values() if not s.completed]))
            EXFIL_REQUESTS.labels(channel=ExfilChannel.HTTP_CHUNKED.value, status="success").inc()

            logger.info(
                "chunked_exfil_completed",
                session_id=chunk.session_id,
                total_size=len(complete_data),
                chunks=session.received_chunks,
            )

            return {
                "status": "completed",
                "checksum": session.checksum,
                "total_size": len(complete_data),
            }

        return {
            "status": "chunk_received",
            "chunks_received": session.received_chunks,
            "chunks_remaining": session.total_chunks - session.received_chunks,
        }


# DNS Exfiltration (simulated - actual DNS would need separate UDP server)
@app.get("/dns/{subdomain}")
async def dns_exfil_simulation(subdomain: str, request: Request):
    """
    Simulate DNS exfiltration.
    In practice, DNS exfil sends data as subdomains:
    data.data.data.exfil.example.com
    """
    client_ip = request.client.host

    # Decode subdomain data (hex or base32 encoded typically)
    try:
        # Try hex decode
        data = bytes.fromhex(subdomain.replace("-", ""))
    except ValueError:
        try:
            # Try base32
            import base64
            data = base64.b32decode(subdomain.upper() + "=" * (8 - len(subdomain) % 8))
        except Exception:
            data = subdomain.encode()

    EXFIL_BYTES.labels(channel=ExfilChannel.DNS_TXT.value).inc(len(data))
    EXFIL_REQUESTS.labels(channel=ExfilChannel.DNS_TXT.value, status="success").inc()

    logger.info(
        "dns_exfil_received",
        subdomain=subdomain,
        decoded_size=len(data),
        source_ip=client_ip,
    )

    # Return fake DNS response
    return Response(
        content=b"",
        media_type="application/dns-message",
        status_code=200,
    )


# Management API
@app.get("/api/sessions")
async def list_sessions(completed: Optional[bool] = None):
    """List exfiltration sessions."""
    result = list(sessions.values())
    if completed is not None:
        result = [s for s in result if s.completed == completed]

    return {
        "sessions": [s.model_dump() for s in result],
        "total": len(result),
    }


@app.get("/api/sessions/{session_id}")
async def get_session(session_id: str):
    """Get session details."""
    if session_id not in sessions:
        raise HTTPException(status_code=404, detail="Session not found")
    return sessions[session_id]


@app.get("/api/sessions/{session_id}/download")
async def download_exfil_data(session_id: str):
    """Download exfiltrated data."""
    if session_id not in sessions:
        raise HTTPException(status_code=404, detail="Session not found")

    session = sessions[session_id]
    if not session.completed:
        raise HTTPException(status_code=400, detail="Session not complete")

    file_path = f"/app/data/exfil/{session.filename}"
    if not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail="File not found")

    async with aiofiles.open(file_path, 'rb') as f:
        content = await f.read()

    return Response(
        content=content,
        media_type="application/octet-stream",
        headers={"Content-Disposition": f"attachment; filename={session.filename}"}
    )


@app.get("/api/stats")
async def get_stats():
    """Get exfiltration statistics."""
    total_bytes = sum(s.total_size or 0 for s in sessions.values() if s.completed)
    return {
        "total_sessions": len(sessions),
        "completed_sessions": len([s for s in sessions.values() if s.completed]),
        "active_sessions": len([s for s in sessions.values() if not s.completed]),
        "total_bytes_exfiltrated": total_bytes,
        "channels_used": list(set(s.channel.value for s in sessions.values())),
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
