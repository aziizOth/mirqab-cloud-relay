"""Mirqab Cloud Relay - Payload Service.

Serves test payloads for security controls validation.
Includes EICAR test files and other safe detection test files.
"""
import logging
import time
from contextlib import asynccontextmanager
from datetime import datetime
from pathlib import Path
from typing import Optional
from uuid import UUID

from fastapi import FastAPI, Depends, HTTPException, Request, Query
from fastapi.responses import FileResponse, JSONResponse
from sqlalchemy import func
from sqlalchemy.orm import Session

from .config import settings
from .database import get_db, init_db, get_db_context
from .models import Payload, PayloadRequest, PayloadCategory, DownloadResult
from .schemas import (
    PayloadResponse,
    PayloadListResponse,
    PayloadStatsResponse,
    HealthResponse,
)
from .seed_payloads import ensure_payloads_seeded

# Configure logging
logging.basicConfig(
    level=getattr(logging, settings.LOG_LEVEL),
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan events."""
    # Startup
    logger.info("Starting Payload Service...")

    # Initialize database
    init_db()
    logger.info("Database initialized")

    # Seed payloads
    with get_db_context() as db:
        count = ensure_payloads_seeded(db)
        if count > 0:
            logger.info(f"Seeded {count} new payloads")
        else:
            logger.info("All payloads already seeded")

    yield

    # Shutdown
    logger.info("Shutting down Payload Service...")


app = FastAPI(
    title="Mirqab Payload Service",
    description="Security test payload delivery service for Cloud Relay",
    version=settings.VERSION,
    lifespan=lifespan,
)


def log_request(
    db: Session,
    payload: Optional[Payload],
    request: Request,
    result: DownloadResult,
    response_code: int,
    response_time_ms: int,
) -> PayloadRequest:
    """Log a payload download request."""
    log_entry = PayloadRequest(
        payload_id=payload.id if payload else None,
        tenant_id=request.headers.get("X-Tenant-ID"),
        agent_id=request.headers.get("X-Agent-ID"),
        source_ip=request.client.host if request.client else None,
        user_agent=request.headers.get("User-Agent"),
        result=result,
        response_code=response_code,
        execution_id=request.headers.get("X-Execution-ID"),
        requested_at=datetime.utcnow(),
        response_time_ms=response_time_ms,
    )
    db.add(log_entry)
    db.commit()
    return log_entry


# =============================================================================
# Health Endpoints
# =============================================================================

@app.get("/health", response_model=HealthResponse)
def health_check(db: Session = Depends(get_db)):
    """Health check endpoint."""
    try:
        count = db.query(func.count(Payload.id)).scalar()
        return HealthResponse(
            status="healthy",
            service=settings.SERVICE_NAME,
            version=settings.VERSION,
            database="connected",
            payloads_count=count,
        )
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        return JSONResponse(
            status_code=503,
            content={
                "status": "unhealthy",
                "service": settings.SERVICE_NAME,
                "version": settings.VERSION,
                "database": "disconnected",
                "error": str(e),
            }
        )


# =============================================================================
# Download Endpoints (Public - for agents)
# =============================================================================

@app.get("/download/{filename:path}")
async def download_payload(
    filename: str,
    request: Request,
    db: Session = Depends(get_db),
):
    """Download a payload file.

    This endpoint serves test payloads for security validation.
    All payloads are safe (EICAR-based) and should be detected by AV.
    """
    start_time = time.time()

    # Find payload by filename
    payload = db.query(Payload).filter(
        Payload.filename == filename,
        Payload.enabled == True,
    ).first()

    if not payload:
        # Log the failed request
        response_time_ms = int((time.time() - start_time) * 1000)
        log_request(db, None, request, DownloadResult.ERROR, 404, response_time_ms)
        raise HTTPException(status_code=404, detail=f"Payload not found: {filename}")

    # Check if file exists
    file_path = Path(payload.file_path)
    if not file_path.exists():
        response_time_ms = int((time.time() - start_time) * 1000)
        log_request(db, payload, request, DownloadResult.ERROR, 500, response_time_ms)
        logger.error(f"Payload file missing: {file_path}")
        raise HTTPException(status_code=500, detail="Payload file not found on disk")

    # Log successful request
    response_time_ms = int((time.time() - start_time) * 1000)
    log_request(db, payload, request, DownloadResult.DOWNLOADED, 200, response_time_ms)

    logger.info(
        f"Payload downloaded: {filename} by {request.client.host} "
        f"(agent={request.headers.get('X-Agent-ID', 'unknown')})"
    )

    return FileResponse(
        path=file_path,
        filename=payload.filename,
        media_type=payload.mime_type,
        headers={
            "X-Payload-ID": str(payload.id),
            "X-Payload-SHA256": payload.sha256,
            "X-Expected-Detection": payload.expected_detection or "",
        }
    )


@app.get("/stage/{filename:path}")
async def stage_payload(
    filename: str,
    request: Request,
    db: Session = Depends(get_db),
):
    """Download a staged payload (scripts, etc.).

    Staged payloads are typically scripts that would be executed
    by PowerShell, bash, or other interpreters.
    """
    start_time = time.time()

    # Find payload by filename (look in stage directory first)
    payload = db.query(Payload).filter(
        Payload.filename == filename,
        Payload.enabled == True,
    ).first()

    if not payload:
        response_time_ms = int((time.time() - start_time) * 1000)
        log_request(db, None, request, DownloadResult.ERROR, 404, response_time_ms)
        raise HTTPException(status_code=404, detail=f"Staged payload not found: {filename}")

    # Check if file exists
    file_path = Path(payload.file_path)
    if not file_path.exists():
        response_time_ms = int((time.time() - start_time) * 1000)
        log_request(db, payload, request, DownloadResult.ERROR, 500, response_time_ms)
        logger.error(f"Staged payload file missing: {file_path}")
        raise HTTPException(status_code=500, detail="Staged payload file not found on disk")

    # Log successful request
    response_time_ms = int((time.time() - start_time) * 1000)
    log_request(db, payload, request, DownloadResult.DOWNLOADED, 200, response_time_ms)

    logger.info(
        f"Staged payload downloaded: {filename} by {request.client.host} "
        f"(agent={request.headers.get('X-Agent-ID', 'unknown')})"
    )

    return FileResponse(
        path=file_path,
        filename=payload.filename,
        media_type=payload.mime_type,
        headers={
            "X-Payload-ID": str(payload.id),
            "X-Payload-SHA256": payload.sha256,
            "X-Expected-Detection": payload.expected_detection or "",
        }
    )


# =============================================================================
# Admin/API Endpoints (for management)
# =============================================================================

@app.get("/payloads", response_model=PayloadListResponse)
def list_payloads(
    category: Optional[PayloadCategory] = Query(None),
    enabled_only: bool = Query(True),
    db: Session = Depends(get_db),
):
    """List all available payloads."""
    query = db.query(Payload)

    if category:
        query = query.filter(Payload.category == category)
    if enabled_only:
        query = query.filter(Payload.enabled == True)

    payloads = query.order_by(Payload.category, Payload.filename).all()

    items = []
    for p in payloads:
        # Determine download URL based on category
        if p.category == PayloadCategory.SCRIPT:
            download_url = f"/stage/{p.filename}"
        else:
            download_url = f"/download/{p.filename}"

        items.append(PayloadResponse(
            id=p.id,
            name=p.name,
            filename=p.filename,
            category=p.category,
            subcategory=p.subcategory,
            mime_type=p.mime_type,
            file_size=p.file_size,
            sha256=p.sha256,
            description=p.description,
            mitre_technique_id=p.mitre_technique_id,
            expected_detection=p.expected_detection,
            safety_level=p.safety_level,
            enabled=p.enabled,
            created_at=p.created_at,
            download_url=download_url,
        ))

    return PayloadListResponse(total=len(items), items=items)


@app.get("/payloads/{payload_id}", response_model=PayloadResponse)
def get_payload(
    payload_id: UUID,
    db: Session = Depends(get_db),
):
    """Get details of a specific payload."""
    payload = db.query(Payload).filter(Payload.id == payload_id).first()

    if not payload:
        raise HTTPException(status_code=404, detail="Payload not found")

    if payload.category == PayloadCategory.SCRIPT:
        download_url = f"/stage/{payload.filename}"
    else:
        download_url = f"/download/{payload.filename}"

    return PayloadResponse(
        id=payload.id,
        name=payload.name,
        filename=payload.filename,
        category=payload.category,
        subcategory=payload.subcategory,
        mime_type=payload.mime_type,
        file_size=payload.file_size,
        sha256=payload.sha256,
        description=payload.description,
        mitre_technique_id=payload.mitre_technique_id,
        expected_detection=payload.expected_detection,
        safety_level=payload.safety_level,
        enabled=payload.enabled,
        created_at=payload.created_at,
        download_url=download_url,
    )


@app.get("/payloads/{payload_id}/stats", response_model=PayloadStatsResponse)
def get_payload_stats(
    payload_id: UUID,
    db: Session = Depends(get_db),
):
    """Get download statistics for a payload."""
    payload = db.query(Payload).filter(Payload.id == payload_id).first()

    if not payload:
        raise HTTPException(status_code=404, detail="Payload not found")

    # Get statistics
    total = db.query(func.count(PayloadRequest.id)).filter(
        PayloadRequest.payload_id == payload_id
    ).scalar()

    successful = db.query(func.count(PayloadRequest.id)).filter(
        PayloadRequest.payload_id == payload_id,
        PayloadRequest.result == DownloadResult.DOWNLOADED,
    ).scalar()

    blocked = db.query(func.count(PayloadRequest.id)).filter(
        PayloadRequest.payload_id == payload_id,
        PayloadRequest.result == DownloadResult.BLOCKED,
    ).scalar()

    unique_agents = db.query(func.count(func.distinct(PayloadRequest.agent_id))).filter(
        PayloadRequest.payload_id == payload_id,
        PayloadRequest.agent_id.isnot(None),
    ).scalar()

    last_download = db.query(func.max(PayloadRequest.requested_at)).filter(
        PayloadRequest.payload_id == payload_id,
        PayloadRequest.result == DownloadResult.DOWNLOADED,
    ).scalar()

    return PayloadStatsResponse(
        payload_id=payload_id,
        filename=payload.filename,
        total_downloads=total,
        successful_downloads=successful,
        blocked_downloads=blocked,
        unique_agents=unique_agents,
        last_download=last_download,
    )


# =============================================================================
# Run with uvicorn
# =============================================================================

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "app.main:app",
        host=settings.HOST,
        port=settings.PORT,
        reload=settings.DEBUG,
    )
