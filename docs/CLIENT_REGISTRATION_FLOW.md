# Client Registration & Cloud Relay Connection Flow

## Overview

When a client purchases a Mirqab license and deploys the Master Server OVA, they need to:
1. **Activate their license** with Mirqab Command Center
2. **Get provisioned as a tenant** in the Cloud Relay infrastructure
3. **Receive credentials** to connect their Master Server to Cloud Relay services

This document describes the complete flow.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                           MIRQAB INFRASTRUCTURE                                  │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                  │
│  ┌────────────────────────┐         ┌─────────────────────────────────────────┐ │
│  │   COMMAND CENTER       │         │           CLOUD RELAY                   │ │
│  │   (api.mirqab.io)      │         │        (relay.mirqab.io)                │ │
│  │                        │         │                                         │ │
│  │  1. License Validation │ ──────> │  2. Tenant Provisioning                 │ │
│  │  3. Generate API Keys  │         │     - Create Namespace                  │ │
│  │  4. Return Credentials │         │     - Deploy C2 Services                │ │
│  │                        │         │     - Generate TLS Certs                │ │
│  └───────────┬────────────┘         │     - Create DNS Records                │ │
│              │                      │                                         │ │
│              │                      │  Per-Tenant Services:                   │ │
│              │                      │  - c2-http.tenant-xxx.relay.mirqab.io   │ │
│              │                      │  - c2-dns: xxx.c2.mirqab.io             │ │
│              │                      │  - payloads.tenant-xxx.relay.mirqab.io  │ │
│              │                      └─────────────────────────────────────────┘ │
│              │                                        │                         │
└──────────────┼────────────────────────────────────────┼─────────────────────────┘
               │                                        │
               │ 5. Return Credentials                  │ 6. Encrypted Connection
               │    & Relay Endpoints                   │    (mTLS)
               ▼                                        ▼
┌─────────────────────────────────────────────────────────────────────────────────┐
│                           CLIENT INFRASTRUCTURE                                  │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                  │
│  ┌─────────────────────────────────────────────────────────────────────────┐   │
│  │                    MASTER SERVER (OVA)                                   │   │
│  │                    mirqab-security-sentinel                              │   │
│  │                                                                          │   │
│  │  On First Boot:                                                          │   │
│  │  ┌─────────────────────────────────────────────────────────────────┐    │   │
│  │  │  Setup Wizard                                                    │    │   │
│  │  │  1. Enter License Key (provided at purchase)                     │    │   │
│  │  │  2. Enter Organization Name                                      │    │   │
│  │  │  3. Click "Activate & Connect"                                   │    │   │
│  │  │                                                                  │    │   │
│  │  │  Backend Process:                                                │    │   │
│  │  │  - Calls Command Center API to validate license                  │    │   │
│  │  │  - Command Center provisions tenant in Cloud Relay               │    │   │
│  │  │  - Returns: API Key, Relay Endpoints, TLS Certificate            │    │   │
│  │  │  - Master Server stores credentials securely                     │    │   │
│  │  │  - Establishes mTLS connection to Cloud Relay                    │    │   │
│  │  └─────────────────────────────────────────────────────────────────┘    │   │
│  │                                                                          │   │
│  │  After Activation:                                                       │   │
│  │  - Periodic license heartbeat to Command Center                         │   │
│  │  - mTLS connection to Cloud Relay for attack simulations                │   │
│  │  - Content sync from Command Center (attack library updates)            │   │
│  │                                                                          │   │
│  └─────────────────────────────────────────────────────────────────────────┘   │
│                                                                                  │
└─────────────────────────────────────────────────────────────────────────────────┘
```

---

## Step-by-Step Flow

### Step 1: Client Purchases License

**Mirqab Sales Process:**
1. Client purchases license tier (Starter/Professional/Enterprise)
2. Mirqab generates a **License Key** in Command Center
3. Client receives:
   - License Key (e.g., `MIRQAB-XXXX-XXXX-XXXX-XXXX`)
   - Master Server OVA download link
   - Setup Guide PDF

**License Key Format:**
```
MIRQAB-{TIER}-{RANDOM}-{CHECKSUM}

Example: MIRQAB-PRO-A7B2C9D4-E5F6
```

### Step 2: Client Deploys Master Server OVA

1. Client imports OVA into VMware/VirtualBox/Hyper-V
2. Configures network settings (IP, DNS)
3. Boots the VM
4. Accesses web UI: `https://<server-ip>:8443/setup`

### Step 3: License Activation (Setup Wizard)

**Client enters in Setup Wizard:**
- License Key
- Organization Name
- Admin Email
- Admin Password

**API Call from Master Server to Command Center:**

```http
POST https://api.mirqab.io/v1/licenses/activate
Content-Type: application/json

{
  "license_key": "MIRQAB-PRO-A7B2C9D4-E5F6",
  "organization_name": "Acme Corporation",
  "admin_email": "admin@acme.com",
  "server_fingerprint": "sha256:abc123...",  // Unique hardware ID
  "server_version": "2.4.1",
  "ip_address": "203.0.113.50"  // For geo-routing
}
```

### Step 4: Command Center Validates & Provisions

**Command Center Backend:**

1. **Validate License Key**
   - Check signature
   - Check not already activated
   - Check not expired/revoked

2. **Create Tenant Record**
   ```sql
   INSERT INTO tenants (id, name, license_key, tier, status)
   VALUES (uuid(), 'Acme Corporation', 'MIRQAB-PRO-...', 'professional', 'active');
   ```

3. **Provision Cloud Relay Tenant**
   - Call Cloud Relay Provisioning API
   - Create Kubernetes namespace: `tenant-acme-corp-uuid`
   - Deploy C2 services (HTTP, DNS, Payload)
   - Generate TLS certificates
   - Create DNS records

4. **Generate Credentials**
   - API Key for Command Center (license heartbeat)
   - API Key for Cloud Relay (attack simulation)
   - mTLS client certificate

### Step 5: Return Credentials to Master Server

**Command Center Response:**

```json
{
  "status": "activated",
  "tenant_id": "tenant-a7b2c9d4",
  "organization": "Acme Corporation",
  "tier": "professional",
  "expires_at": "2027-01-11T00:00:00Z",

  "command_center": {
    "api_key": "cc_live_xxxxxxxxxxxxxxxxxxxxxxxx",
    "endpoint": "https://api.mirqab.io",
    "heartbeat_interval": 3600
  },

  "cloud_relay": {
    "api_key": "cr_live_xxxxxxxxxxxxxxxxxxxxxxxx",
    "endpoints": {
      "c2_http": "https://c2-http.tenant-a7b2c9d4.relay.mirqab.io",
      "c2_dns": "a7b2c9d4.c2.mirqab.io",
      "payloads": "https://payloads.tenant-a7b2c9d4.relay.mirqab.io",
      "exfil": "https://exfil.tenant-a7b2c9d4.relay.mirqab.io"
    },
    "tls_certificate": "-----BEGIN CERTIFICATE-----\n...",
    "tls_private_key": "-----BEGIN PRIVATE KEY-----\n...",  // Encrypted
    "ca_certificate": "-----BEGIN CERTIFICATE-----\n..."
  },

  "features": {
    "max_agents": 50,
    "max_concurrent_executions": 10,
    "c2_http": true,
    "c2_dns": true,
    "payload_hosting": true,
    "custom_domains": false
  }
}
```

### Step 6: Master Server Stores Credentials

Master Server securely stores:
- Credentials in encrypted config: `/etc/mirqab/relay.conf`
- TLS certificates: `/etc/mirqab/certs/`

```python
# /etc/mirqab/relay.conf (encrypted with master key)
{
  "tenant_id": "tenant-a7b2c9d4",
  "command_center": {
    "api_key": "cc_live_xxx",
    "endpoint": "https://api.mirqab.io"
  },
  "cloud_relay": {
    "api_key": "cr_live_xxx",
    "endpoints": {...}
  }
}
```

### Step 7: Establish Connection to Cloud Relay

Master Server establishes mTLS connection:

```python
# Master Server connects to Cloud Relay
import httpx

client = httpx.Client(
    cert=("/etc/mirqab/certs/client.crt", "/etc/mirqab/certs/client.key"),
    verify="/etc/mirqab/certs/ca.crt",
    headers={"X-API-Key": cloud_relay_api_key}
)

# Test connection
response = client.get("https://c2-http.tenant-a7b2c9d4.relay.mirqab.io/health")
```

---

## Ongoing Operations

### License Heartbeat (Every Hour)

```http
POST https://api.mirqab.io/v1/licenses/heartbeat
Authorization: Bearer cc_live_xxx
Content-Type: application/json

{
  "tenant_id": "tenant-a7b2c9d4",
  "server_fingerprint": "sha256:abc123...",
  "version": "2.4.1",
  "metrics": {
    "active_agents": 12,
    "executions_today": 45,
    "last_execution": "2026-01-11T10:30:00Z"
  }
}
```

### Attack Simulation Flow

When client runs an attack that needs Cloud Relay:

```
1. User clicks "Run Attack" in Security Sentinel UI
2. Master Server creates execution record
3. Master Server sends command to local Agent
4. Agent connects to Cloud Relay endpoint (e.g., C2 HTTP)
5. Cloud Relay responds with simulated C2 traffic
6. Agent reports results back to Master Server
7. Master Server logs detection/block status
```

---

## Tenant Isolation in Cloud Relay

Each tenant gets:
- **Unique Kubernetes Namespace**: `tenant-{tenant_id}`
- **Unique DNS Subdomain**: `{tenant_id}.c2.mirqab.io`
- **Unique TLS Certificate**: Issued per tenant
- **Resource Quotas**: Based on tier
- **Network Policies**: Cannot see other tenants

```yaml
# Tenant namespace example
apiVersion: v1
kind: Namespace
metadata:
  name: tenant-a7b2c9d4
  labels:
    mirqab.io/tenant-id: a7b2c9d4
    mirqab.io/tier: professional
```

---

## Security Considerations

1. **License Key Security**
   - One-time activation (bound to server fingerprint)
   - Cannot be reused on different servers
   - Revocable from Command Center

2. **API Key Security**
   - Separate keys for Command Center and Cloud Relay
   - Keys can be rotated without license reactivation
   - Rate limited per tenant

3. **mTLS**
   - All Cloud Relay connections require client certificate
   - Certificates tied to tenant ID
   - 1-year validity, auto-renewal

4. **Tenant Isolation**
   - Kubernetes NetworkPolicies prevent cross-tenant traffic
   - gVisor sandboxing for container isolation
   - Per-tenant resource quotas

---

## Error Handling

| Error | Cause | Resolution |
|-------|-------|------------|
| `LICENSE_INVALID` | Bad license key | Check key, contact sales |
| `LICENSE_EXPIRED` | License expired | Renew subscription |
| `LICENSE_REVOKED` | License revoked | Contact Mirqab support |
| `ALREADY_ACTIVATED` | Key used on another server | Use correct server or contact support |
| `QUOTA_EXCEEDED` | Too many agents/executions | Upgrade tier |
| `RELAY_UNAVAILABLE` | Cloud Relay down | Check status.mirqab.io |

---

## Sequence Diagram

```
┌────────┐     ┌──────────────┐     ┌─────────────────┐     ┌─────────────┐
│ Client │     │ Master Server│     │ Command Center  │     │ Cloud Relay │
└───┬────┘     └──────┬───────┘     └────────┬────────┘     └──────┬──────┘
    │                 │                       │                     │
    │ 1. Enter License Key                    │                     │
    │────────────────>│                       │                     │
    │                 │                       │                     │
    │                 │ 2. POST /licenses/activate                  │
    │                 │──────────────────────>│                     │
    │                 │                       │                     │
    │                 │                       │ 3. Validate License │
    │                 │                       │─────────┐           │
    │                 │                       │<────────┘           │
    │                 │                       │                     │
    │                 │                       │ 4. Provision Tenant │
    │                 │                       │────────────────────>│
    │                 │                       │                     │
    │                 │                       │                     │ 5. Create Namespace
    │                 │                       │                     │    Deploy Services
    │                 │                       │                     │    Generate Certs
    │                 │                       │                     │─────────┐
    │                 │                       │                     │<────────┘
    │                 │                       │                     │
    │                 │                       │ 6. Return Endpoints │
    │                 │                       │<────────────────────│
    │                 │                       │                     │
    │                 │ 7. Return Credentials │                     │
    │                 │<──────────────────────│                     │
    │                 │                       │                     │
    │                 │ 8. Store Credentials  │                     │
    │                 │─────────┐             │                     │
    │                 │<────────┘             │                     │
    │                 │                       │                     │
    │                 │ 9. Connect to Cloud Relay (mTLS)            │
    │                 │────────────────────────────────────────────>│
    │                 │                       │                     │
    │ 10. Activation Complete                 │                     │
    │<────────────────│                       │                     │
    │                 │                       │                     │
```
