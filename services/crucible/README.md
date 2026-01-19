# Mirqab Crucible

Isolated malware/ransomware execution environment for EDR/AV validation testing.

## Overview

Crucible provides a safe, isolated environment to execute malware samples and validate that EDR/AV solutions detect them correctly. All tests run in disposable VMs with complete network isolation.

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                     Crucible Controller                         │
│  ┌──────────────┐ ┌──────────────┐ ┌──────────────────────────┐│
│  │VM Lifecycle  │ │  Snapshot    │ │    Safety Controller     ││
│  │  Manager     │ │  Manager     │ │  (Isolation Verification)││
│  └──────────────┘ └──────────────┘ └──────────────────────────┘│
│  ┌──────────────┐ ┌──────────────┐ ┌──────────────────────────┐│
│  │   Payload    │ │     EDR      │ │    Test Orchestrator     ││
│  │   Manager    │ │ Integration  │ │                          ││
│  └──────────────┘ └──────────────┘ └──────────────────────────┘│
└───────────────────────────┬─────────────────────────────────────┘
                            │
              Isolated Network (No Internet)
                            │
         ┌──────────────────┼──────────────────┐
         │                  │                  │
    ┌────▼────┐       ┌────▼────┐       ┌────▼────┐
    │Crucible │       │Crucible │       │Crucible │
    │  VM 1   │       │  VM 2   │       │  VM N   │
    │         │       │         │       │         │
    │┌───────┐│       │┌───────┐│       │┌───────┐│
    ││Agent  ││       ││Agent  ││       ││Agent  ││
    │└───────┘│       │└───────┘│       │└───────┘│
    │┌───────┐│       │┌───────┐│       │┌───────┐│
    ││EDR/AV ││       ││EDR/AV ││       ││EDR/AV ││
    │└───────┘│       │└───────┘│       │└───────┘│
    └─────────┘       └─────────┘       └─────────┘
```

## Components

### Crucible Controller (`src/controller.py`)
- VM lifecycle management (create, start, stop, destroy)
- Snapshot management (baseline creation, restore after tests)
- Hypervisor abstraction (libvirt/KVM, VirtualBox, VMware)
- Isolation verification before test execution

### Safety Controller (`src/safety.py`)
- Pre-test isolation verification
- Runtime monitoring during test execution
- Emergency shutdown (kill switch)
- Automatic cleanup on anomalies

### Crucible Agent (`src/agent.py`)
- Runs inside isolated VMs
- Receives encrypted malware payloads
- Executes samples in controlled manner
- Monitors for EDR/AV detections
- Self-verifies network isolation

### EDR Integration (`src/edr_integration.py`)
- CrowdStrike Falcon API
- SentinelOne API
- Microsoft Defender for Endpoint API
- Standardized detection event format

### Payload Manager (`src/payload_manager.py`)
- AES-256-GCM encryption at rest
- Per-delivery unique encryption keys
- SHA256 integrity verification
- Payload library management

## Safety Measures

1. **Network Isolation**: VMs run on isolated internal network with no internet access
2. **Firewall Hardening**: Host and guest firewalls block all external traffic
3. **Snapshot Restore**: After every test, VM is restored to clean baseline
4. **Isolation Verification**: Multiple checks before any malware execution
5. **Emergency Shutdown**: Kill switch to terminate all operations
6. **Secure Payloads**: All malware encrypted at rest and in transit

## Usage

### Building the Golden Image

```bash
cd packer
packer build -var "iso_path=./windows10.iso" crucible-golden.pkr.hcl
```

### Controller Example

```python
import asyncio
from crucible import CrucibleController, VMConfig, HypervisorType

async def main():
    # Initialize controller
    controller = CrucibleController(
        hypervisor_type=HypervisorType.LIBVIRT
    )

    # Create VM instance
    config = VMConfig(
        name="test-edr",
        base_image="/path/to/crucible-golden.ova",
        memory_mb=4096,
        vcpus=2,
    )
    instance = await controller.create_instance(config)

    # Start and verify isolation
    await controller.start_instance(instance.instance_id)
    is_isolated = await controller.verify_isolation(instance.instance_id)

    if not is_isolated:
        raise RuntimeError("Isolation verification failed!")

    # Run tests...

    # Restore to clean state after test
    await controller.restore_instance(instance.instance_id)

    # Cleanup
    await controller.destroy_instance(instance.instance_id)

asyncio.run(main())
```

### Agent Example (runs inside VM)

```python
import asyncio
from crucible import CrucibleAgent

async def main():
    agent = CrucibleAgent(
        controller_url="https://controller:9443",
        api_key="agent-api-key",
        agent_id="vm-001",
    )
    await agent.start()

    # Agent now listens for execution commands...

asyncio.run(main())
```

### EDR Integration Example

```python
from crucible import CrowdStrikeClient, EDRManager
from datetime import datetime, timedelta, timezone

async def check_detections():
    # Initialize EDR clients
    cs_client = CrowdStrikeClient(
        client_id="your-client-id",
        client_secret="your-client-secret",
    )

    # Create manager
    manager = EDRManager()
    manager.register_client("crowdstrike", cs_client)

    # Authenticate
    await manager.authenticate_all()

    # Query detections from last hour
    start_time = datetime.now(timezone.utc) - timedelta(hours=1)
    detections = await manager.get_all_detections(start_time)

    for detection in detections:
        print(f"{detection.source}: {detection.threat_name} ({detection.severity.value})")

    await manager.close_all()
```

## Test Workflow

1. **Initialize**: Create VM from golden image, create baseline snapshot
2. **Pre-check**: Verify network isolation on both host and guest
3. **Deliver**: Encrypt and send malware payload to agent
4. **Execute**: Agent decrypts and executes payload
5. **Monitor**: Watch for EDR detections via APIs
6. **Collect**: Gather detection events, process events, network events
7. **Restore**: Revert VM to baseline snapshot
8. **Report**: Generate test results with detection metrics

## Configuration

Environment variables:

| Variable | Description | Default |
|----------|-------------|---------|
| CRUCIBLE_MASTER_KEY | Master encryption key (base64) | Generated |
| CRUCIBLE_STORAGE_DIR | Payload storage directory | /var/lib/crucible |
| CRUCIBLE_HYPERVISOR | Hypervisor type (libvirt/virtualbox/vmware) | libvirt |

## Security Considerations

- Never run Crucible on production networks
- Always verify isolation before executing malware
- Keep golden images updated with latest security patches
- Rotate API keys regularly
- Monitor for any escape attempts
- Have a physical network isolation strategy as backup

## License

Proprietary - OffenSight Security Testing Suite
