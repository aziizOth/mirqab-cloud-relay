# Network Actors Architecture

## Overview

Network Actors are OVA-based agents that temporarily expose services for security validation testing. They enable testing of network-based attack scenarios by providing controlled, source-restricted service exposure with comprehensive logging.

## Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                           OFFENSIGHT MASTER                                      │
│  ┌─────────────────────────────────────────────────────────────────────────────┐│
│  │                      ATTACK ORCHESTRATION                                    ││
│  │                                                                              ││
│  │  1. User initiates attack requiring Network Actor                           ││
│  │  2. Master sends "open_service" task to Network Actor                       ││
│  │  3. Master sends attack task to Source Agent                                ││
│  │  4. Source Agent executes attack against Network Actor                      ││
│  │  5. Network Actor logs all access, reports to Master                        ││
│  │  6. Master sends "close_service" task (or auto-timeout)                     ││
│  │                                                                              ││
│  └──────────────────────────────┬───────────────────────────────────────────────┘│
└─────────────────────────────────┼───────────────────────────────────────────────┘
                                  │
           ┌──────────────────────┴──────────────────────┐
           │                                              │
           ▼                                              ▼
┌─────────────────────────┐                 ┌─────────────────────────┐
│     SOURCE AGENT        │                 │     NETWORK ACTOR       │
│     (Attacker Host)     │                 │     (OVA Agent)         │
│                         │                 │                         │
│  ┌───────────────────┐  │                 │  ┌───────────────────┐  │
│  │ Attack Tools      │  │  ──────────▶    │  │ Service Control   │  │
│  │ - Impacket        │  │  SMB/RDP/SSH    │  │ - Start/Stop      │  │
│  │ - Hydra           │  │  HTTP           │  │ - Auto-timeout    │  │
│  │ - Custom scripts  │  │                 │  │ - Health check    │  │
│  └───────────────────┘  │                 │  └───────────────────┘  │
│                         │                 │                         │
│                         │                 │  ┌───────────────────┐  │
│                         │                 │  │ Firewall Manager  │  │
│                         │                 │  │ - Source IP only  │  │
│                         │                 │  │ - Auto-cleanup    │  │
│                         │                 │  └───────────────────┘  │
│                         │                 │                         │
│                         │                 │  ┌───────────────────┐  │
│                         │                 │  │ Access Logger     │  │
│                         │                 │  │ - JSON logs       │  │
│                         │                 │  │ - Statistics      │  │
│                         │                 │  │ - SIEM export     │  │
│                         │                 │  └───────────────────┘  │
└─────────────────────────┘                 └─────────────────────────┘
```

## Component Architecture

### 1. Service Controller (`service_control.py`)

Manages the lifecycle of exposed services with configurable timeouts and health monitoring.

```
┌─────────────────────────────────────────────────────────────────┐
│                    SERVICE CONTROLLER                            │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐         │
│  │ ServiceType │    │ServiceState │    │ServiceConfig│         │
│  ├─────────────┤    ├─────────────┤    ├─────────────┤         │
│  │ SMB         │    │ STOPPED     │    │ port        │         │
│  │ RDP         │    │ STARTING    │    │ systemd_unit│         │
│  │ SSH         │    │ RUNNING     │    │ docker      │         │
│  │ HTTP        │    │ STOPPING    │    │ health_check│         │
│  │ HTTPS       │    │ ERROR       │    └─────────────┘         │
│  └─────────────┘    └─────────────┘                             │
│                                                                  │
│  ┌─────────────────────────────────────────────────────────────┐│
│  │                   ServiceSession                             ││
│  │  • session_id      • service_type    • allowed_source_ip    ││
│  │  • state           • started_at      • timeout_at           ││
│  │  • task_id         • execution_id    • access_count         ││
│  └─────────────────────────────────────────────────────────────┘│
│                                                                  │
│  Methods:                                                        │
│  • start_service(session_id, service_type, allowed_source_ip)  │
│  • stop_service(session_id, reason)                             │
│  • health_check(service_type)                                   │
│  • stop_all()                                                   │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

**Supported Services:**

| Service | Port | Systemd Unit | Use Case |
|---------|------|--------------|----------|
| SMB | 445 | smbd | File share testing, SMB relay |
| RDP | 3389 | xrdp | Remote desktop testing |
| SSH | 22 | ssh | SSH brute force, key testing |
| HTTP | 80 | nginx | Web application testing |
| HTTPS | 443 | nginx | TLS testing |

### 2. Firewall Manager (`firewall.py`)

Dynamic firewall management with multi-backend support for source-restricted rules.

```
┌─────────────────────────────────────────────────────────────────┐
│                    FIREWALL MANAGER                              │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌─────────────────────────────────────────────────────────────┐│
│  │                  FirewallBackendBase (ABC)                   ││
│  │  • add_rule(rule)                                            ││
│  │  • remove_rule(rule_id)                                      ││
│  │  • list_rules()                                              ││
│  │  • check_rule_exists(rule_id)                                ││
│  └─────────────────────────────────────────────────────────────┘│
│                          │                                       │
│          ┌───────────────┼───────────────┐                      │
│          ▼               ▼               ▼                      │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐               │
│  │ iptables    │ │ nftables    │ │ UFW         │               │
│  │ Backend     │ │ Backend     │ │ Backend     │               │
│  ├─────────────┤ ├─────────────┤ ├─────────────┤               │
│  │ -I INPUT    │ │ add rule ip │ │ allow from  │               │
│  │ -s SOURCE   │ │ saddr SOURCE│ │ SOURCE to   │               │
│  │ --dport PORT│ │ dport PORT  │ │ any port    │               │
│  │ -j ACCEPT   │ │ accept      │ │ PORT        │               │
│  └─────────────┘ └─────────────┘ └─────────────┘               │
│                                                                  │
│  FirewallRule:                                                   │
│  • rule_id       • port          • source_ip                    │
│  • protocol      • action        • comment                      │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

**Rule Example (iptables):**
```bash
iptables -I INPUT -s 192.168.1.100 -p tcp --dport 445 -j ACCEPT \
  -m comment --comment "mirqab-na-session-123"
```

### 3. Access Logger (`access_logger.py`)

Structured logging for all service access with session statistics and SIEM integration.

```
┌─────────────────────────────────────────────────────────────────┐
│                      ACCESS LOGGER                               │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  AccessEventType:                                                │
│  ┌──────────────────┬──────────────────┬──────────────────┐    │
│  │ SERVICE_START    │ SERVICE_STOP     │ CONNECTION_ATTEMPT│    │
│  │ CONN_ESTABLISHED │ CONN_CLOSED      │ AUTH_SUCCESS     │    │
│  │ AUTH_FAILURE     │ DATA_TRANSFER    │ BLOCKED          │    │
│  └──────────────────┴──────────────────┴──────────────────┘    │
│                                                                  │
│  AccessLogEntry:                                                 │
│  {                                                               │
│    "timestamp": "2026-01-19T12:30:00Z",                         │
│    "event_type": "connection_attempt",                          │
│    "session_id": "uuid",                                        │
│    "service_type": "smb",                                       │
│    "source_ip": "192.168.1.100",                                │
│    "source_port": 54321,                                        │
│    "destination_port": 445,                                     │
│    "username": "attacker",                                      │
│    "bytes_sent": 0,                                             │
│    "bytes_received": 0                                          │
│  }                                                               │
│                                                                  │
│  SessionStats:                                                   │
│  • total_connections      • successful_connections              │
│  • failed_connections     • authentication_successes            │
│  • authentication_failures• total_bytes_sent/received           │
│  • unique_source_ips      • blocked_attempts                    │
│                                                                  │
│  Output: /var/log/mirqab-network-actor/access-YYYYMMDD.jsonl    │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### 4. Network Actor Agent (`network_actor_agent.py`)

Main agent that orchestrates all components and communicates with Master.

```
┌─────────────────────────────────────────────────────────────────┐
│                   NETWORK ACTOR AGENT                            │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌─────────────────────────────────────────────────────────────┐│
│  │                    NetworkActorConfig                        ││
│  │  • master_url         • tenant_id        • api_key          ││
│  │  • agent_id           • default_timeout  • max_timeout      ││
│  │  • allowed_services   • firewall_backend • log_dir          ││
│  └─────────────────────────────────────────────────────────────┘│
│                                                                  │
│  ┌─────────────────────────────────────────────────────────────┐│
│  │                      Agent Lifecycle                         ││
│  │                                                              ││
│  │  start() ──▶ register() ──▶ poll_loop() ──▶ handle_task()  ││
│  │                                   │                          ││
│  │                                   ▼                          ││
│  │                          ┌───────────────┐                   ││
│  │                          │ ServiceTask   │                   ││
│  │                          │ • action      │                   ││
│  │                          │ • service_type│                   ││
│  │                          │ • source_ip   │                   ││
│  │                          │ • timeout     │                   ││
│  │                          └───────────────┘                   ││
│  │                                   │                          ││
│  │                    ┌──────────────┴──────────────┐          ││
│  │                    ▼                             ▼          ││
│  │           handle_open_service()        handle_close_service()││
│  │                    │                             │          ││
│  │                    └──────────────┬──────────────┘          ││
│  │                                   ▼                          ││
│  │                        report_task_result()                  ││
│  │                                                              ││
│  └─────────────────────────────────────────────────────────────┘│
│                                                                  │
│  stop() ──▶ stop_all_services() ──▶ cleanup_firewall()         │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

## Service Lifecycle

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                          SERVICE LIFECYCLE                                       │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                  │
│  IDLE                                                                            │
│    │                                                                             │
│    │ Master sends "open_service" task                                           │
│    ▼                                                                             │
│  OPENING                                                                         │
│    ├── 1. Create ServiceSession                                                 │
│    ├── 2. Add firewall rule (source IP restricted)                              │
│    ├── 3. Start systemd service                                                 │
│    ├── 4. Start timeout timer                                                   │
│    └── 5. Log SERVICE_START event                                               │
│    │                                                                             │
│    ▼                                                                             │
│  ACTIVE                                                                          │
│    ├── Accept connections from allowed source IP only                           │
│    ├── Log all connection attempts                                              │
│    ├── Track authentication success/failure                                     │
│    └── Monitor data transfer                                                    │
│    │                                                                             │
│    │ Timeout OR Master sends "close_service" OR Agent shutdown                  │
│    ▼                                                                             │
│  CLOSING                                                                         │
│    ├── 1. Cancel timeout timer                                                  │
│    ├── 2. Remove firewall rule                                                  │
│    ├── 3. Stop systemd service (optional)                                       │
│    ├── 4. Log SERVICE_STOP event                                                │
│    └── 5. Compile session statistics                                            │
│    │                                                                             │
│    ▼                                                                             │
│  REPORTING                                                                       │
│    └── Send session stats to Master                                             │
│    │                                                                             │
│    ▼                                                                             │
│  IDLE                                                                            │
│                                                                                  │
└─────────────────────────────────────────────────────────────────────────────────┘
```

## Security Model

### Firewall Isolation

```
┌─────────────────────────────────────────────────────────────────┐
│                    FIREWALL RULES                                │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  DEFAULT POLICY: DENY ALL INCOMING                               │
│                                                                  │
│  ┌─────────────────────────────────────────────────────────────┐│
│  │ PERMANENT RULES (always active)                              ││
│  │  • ALLOW SSH from management network                         ││
│  │  • ALLOW established/related connections                     ││
│  └─────────────────────────────────────────────────────────────┘│
│                                                                  │
│  ┌─────────────────────────────────────────────────────────────┐│
│  │ DYNAMIC RULES (active only during service session)          ││
│  │                                                              ││
│  │  Session: abc-123                                            ││
│  │  Rule: ALLOW 192.168.1.100 -> tcp/445 (SMB)                 ││
│  │  Comment: mirqab-na-abc-123                                  ││
│  │  TTL: 300 seconds                                            ││
│  │                                                              ││
│  │  Session: def-456                                            ││
│  │  Rule: ALLOW 192.168.1.200 -> tcp/3389 (RDP)                ││
│  │  Comment: mirqab-na-def-456                                  ││
│  │  TTL: 600 seconds                                            ││
│  └─────────────────────────────────────────────────────────────┘│
│                                                                  │
│  CLEANUP: All dynamic rules removed on agent shutdown           │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### Auto-Timeout Protection

```python
# Timeout enforcement
async def _enforce_timeout(self, session_id: str, timeout_seconds: int):
    await asyncio.sleep(timeout_seconds)
    await self.stop_service(session_id, reason="timeout")
```

- **Default timeout**: 300 seconds (5 minutes)
- **Maximum timeout**: 3600 seconds (1 hour)
- **Timeout enforcement**: Asynchronous task cancellation

## API Integration

### Task Structure

**Open Service Request:**
```json
{
  "task_id": "550e8400-e29b-41d4-a716-446655440000",
  "action": "open",
  "service_type": "smb",
  "allowed_source_ip": "192.168.1.100",
  "timeout_seconds": 300,
  "execution_id": "exec-12345",
  "parameters": {}
}
```

**Close Service Request:**
```json
{
  "task_id": "550e8400-e29b-41d4-a716-446655440000",
  "action": "close",
  "service_type": "smb",
  "allowed_source_ip": "192.168.1.100"
}
```

**Task Result:**
```json
{
  "task_id": "550e8400-e29b-41d4-a716-446655440000",
  "execution_id": "exec-12345",
  "success": true,
  "message": "Service smb opened",
  "data": {
    "session_id": "550e8400-e29b-41d4-a716-446655440000",
    "state": "running",
    "timeout_at": "2026-01-19T13:05:00Z"
  },
  "timestamp": "2026-01-19T13:00:00Z"
}
```

### Session Report

```json
{
  "report_type": "network_actor_session",
  "timestamp": "2026-01-19T13:05:00Z",
  "session": {
    "session_id": "550e8400-e29b-41d4-a716-446655440000",
    "service_type": "smb",
    "started_at": "2026-01-19T13:00:00Z",
    "ended_at": "2026-01-19T13:05:00Z",
    "duration_seconds": 300,
    "total_connections": 5,
    "successful_connections": 3,
    "failed_connections": 2,
    "authentication_successes": 2,
    "authentication_failures": 1,
    "total_bytes_sent": 1024,
    "total_bytes_received": 4096,
    "unique_source_ips": ["192.168.1.100"],
    "blocked_attempts": 0
  }
}
```

## Deployment

### OVA Image Contents

```
┌─────────────────────────────────────────────────────────────────┐
│                    NETWORK ACTOR OVA                             │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  Base: Ubuntu 22.04 LTS Server                                  │
│                                                                  │
│  Pre-installed Services (disabled by default):                  │
│  • Samba (SMB)                                                  │
│  • xrdp (RDP)                                                   │
│  • OpenSSH                                                      │
│  • Nginx (HTTP/HTTPS)                                           │
│                                                                  │
│  Firewall: UFW (enabled, default deny)                          │
│                                                                  │
│  Network Actor Agent:                                           │
│  • Location: /opt/mirqab/network-actor/                         │
│  • Service: mirqab-network-actor.service                        │
│  • Config: /etc/mirqab/network-actor.env                        │
│  • Logs: /var/log/mirqab-network-actor/                         │
│                                                                  │
│  Python Environment:                                             │
│  • /opt/mirqab/network-actor/venv/                              │
│  • httpx, aiofiles, structlog                                   │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### Build Process

```bash
cd services/network-actor/packer
packer init .
packer build network-actor.pkr.hcl
```

Output: `mirqab-network-actor.ova`

### Configuration

```bash
# /etc/mirqab/network-actor.env
MASTER_URL=https://api.offensight.local:8000
TENANT_ID=tenant-123
API_KEY=your-api-key
AGENT_ID=network-actor-001
AGENT_NAME=Network Actor DC01
DEFAULT_TIMEOUT=300
MAX_TIMEOUT=3600
POLL_INTERVAL=5.0
LOG_DIR=/var/log/mirqab-network-actor
```

## Use Cases

### 1. SMB Relay Testing

```
Source Agent (Kali) ──────────────────────▶ Network Actor
                     SMB connection         (SMB share exposed
                     to 192.168.1.50:445    only for Kali IP)
```

### 2. RDP Brute Force Testing

```
Source Agent (Kali) ──────────────────────▶ Network Actor
                     RDP brute force        (RDP exposed
                     attempts               only for Kali IP)
```

### 3. SSH Key Testing

```
Source Agent (Kali) ──────────────────────▶ Network Actor
                     SSH with stolen        (SSH exposed
                     private key            only for Kali IP)
```

## File Structure

```
services/network-actor/
├── README.md                           # Service documentation
├── requirements.txt                    # Python dependencies
├── src/
│   ├── __init__.py                    # Module exports
│   ├── service_control.py             # Service lifecycle management
│   ├── firewall.py                    # Dynamic firewall management
│   ├── access_logger.py               # Structured access logging
│   └── network_actor_agent.py         # Main agent
├── packer/
│   ├── network-actor.pkr.hcl          # Packer build configuration
│   └── http/
│       ├── user-data                  # Cloud-init autoinstall
│       └── meta-data                  # Cloud-init metadata
└── tests/
    └── (test files)
```
