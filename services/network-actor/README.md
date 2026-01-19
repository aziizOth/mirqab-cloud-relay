# Mirqab Network Actor

Network Actor agent for controlled service exposure testing.

## Overview

Network Actor is an OVA-based agent that temporarily exposes services (SMB, RDP, SSH, HTTP) for security validation testing. It enforces strict source IP restrictions and automatically closes services after a configurable timeout.

## Features

- **Temporary Service Exposure**: Open services on-demand for testing
- **Source IP Restrictions**: Only allow connections from specified attacker IP
- **Dynamic Firewall Management**: Auto-configures iptables/nftables/UFW
- **Access Logging**: Structured JSON logging for SIEM ingestion
- **Auto-timeout**: Services automatically close after timeout
- **Master Integration**: Polls Master server for tasks, reports results

## Supported Services

| Service | Port | Use Case |
|---------|------|----------|
| SMB | 445 | File share access testing |
| RDP | 3389 | Remote desktop testing |
| SSH | 22 | SSH brute force testing |
| HTTP | 80 | Web server testing |
| HTTPS | 443 | HTTPS testing |

## Lifecycle

```
IDLE → OPENING → ACTIVE → CLOSING → REPORTING → IDLE
         ↓           ↓
    [Firewall   [Accept connections
     rule added] from source IP only]
```

## Deployment

### Option 1: OVA Image

1. Build the OVA using Packer:
   ```bash
   cd packer
   packer build network-actor.pkr.hcl
   ```

2. Import the OVA into your hypervisor (VMware, VirtualBox, etc.)

3. Configure the agent:
   ```bash
   sudo cp /etc/mirqab/network-actor.env.template /etc/mirqab/network-actor.env
   sudo nano /etc/mirqab/network-actor.env
   ```

4. Start the agent:
   ```bash
   sudo systemctl start mirqab-network-actor
   ```

### Option 2: Manual Installation

1. Install dependencies:
   ```bash
   sudo apt-get install -y python3 python3-pip python3-venv ufw samba openssh-server nginx
   ```

2. Install the agent:
   ```bash
   cd services/network-actor
   python3 -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
   ```

3. Configure environment:
   ```bash
   export MASTER_URL=https://api.offensight.local:8000
   export TENANT_ID=your-tenant-id
   export API_KEY=your-api-key
   export AGENT_ID=network-actor-001
   ```

4. Run the agent:
   ```bash
   python -m src.network_actor_agent
   ```

## Configuration

Environment variables:

| Variable | Description | Default |
|----------|-------------|---------|
| MASTER_URL | OffenSight Master URL | https://api.offensight.local:8000 |
| TENANT_ID | Tenant identifier | - |
| API_KEY | API key for authentication | - |
| AGENT_ID | Unique agent identifier | - |
| AGENT_NAME | Human-readable agent name | Agent ID |
| DEFAULT_TIMEOUT | Default service timeout (seconds) | 300 |
| MAX_TIMEOUT | Maximum service timeout (seconds) | 3600 |
| POLL_INTERVAL | Task poll interval (seconds) | 5.0 |
| LOG_DIR | Access log directory | /var/log/mirqab-network-actor |

## Security

- Services are disabled by default, only started when needed
- Firewall rules are source-IP restricted
- All access attempts are logged
- Services auto-close after timeout
- Agent runs with minimal privileges

## API

The agent responds to tasks from Master with this structure:

```json
{
  "task_id": "uuid",
  "action": "open",
  "service_type": "smb",
  "allowed_source_ip": "192.168.1.100",
  "timeout_seconds": 300
}
```

Results are reported back:

```json
{
  "task_id": "uuid",
  "success": true,
  "data": {
    "session_id": "uuid",
    "state": "running",
    "timeout_at": "2026-01-19T13:00:00Z"
  }
}
```

## Access Logs

Logs are written in JSON Lines format to `/var/log/mirqab-network-actor/access-YYYYMMDD.jsonl`:

```json
{
  "timestamp": "2026-01-19T12:30:00Z",
  "event_type": "connection_attempt",
  "session_id": "uuid",
  "service_type": "smb",
  "source_ip": "192.168.1.100",
  "source_port": 54321,
  "destination_port": 445
}
```

## Testing

Run the agent locally for testing:

```python
import asyncio
from src import NetworkActorAgent, NetworkActorConfig, ServiceType

async def test():
    config = NetworkActorConfig(
        master_url="https://localhost:8000",
        tenant_id="test",
        api_key="test-key",
        agent_id="test-agent",
    )
    agent = NetworkActorAgent(config)
    await agent.start()

    # Open SMB for 60 seconds
    session = await agent.open_service(
        ServiceType.SMB,
        allowed_source_ip="192.168.1.100",
        timeout_seconds=60,
    )
    print(f"Session: {session.session_id}")

    # Wait for tests
    await asyncio.sleep(60)

    await agent.stop()

asyncio.run(test())
```
