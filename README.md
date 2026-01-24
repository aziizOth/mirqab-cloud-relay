# Mirqab Cloud Relay

**Self-Contained External Attack Infrastructure**

Cloud Relay is the **external attack platform** for Mirqab Security Validation. It handles ALL attack capabilities for MITRE ATT&CK techniques that require external infrastructure.

## Important: Architecture Clarification

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                           MIRQAB COMPANY (SaaS)                                  │
│  ┌─────────────────────────────────────────────────────────────────────────┐   │
│  │                    COMMAND CENTER (mirqab-command-center)                │   │
│  │                    Management Portal Only - NOT involved in attacks      │   │
│  │    - License management          - Subscription tiers                    │   │
│  │    - Push Sigma rules/CVEs       - Attack definition updates             │   │
│  └─────────────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────────────┘
                                        │ Push feeds, licenses
                                        ▼
┌─────────────────────────────────────────────────────────────────────────────────┐
│                           CUSTOMER ENVIRONMENT                                   │
│  ┌─────────────────────────────────────────────────────────────────────────┐   │
│  │              MASTER SERVER (OffenSight + Security Sentinel)              │   │
│  │              Frontend + Backend - Orchestrates ALL attacks               │   │
│  └──────────────────────────────────┬──────────────────────────────────────┘   │
│                 │                    │                    │                     │
│           ┌─────┴─────┐        ┌─────┴─────┐        ┌─────┴─────┐              │
│           │  Agents   │        │  Crucible │        │  Network  │              │
│           │ (targets) │        │   (VMs)   │        │  Actors   │              │
│           └─────┬─────┘        └───────────┘        └───────────┘              │
│                 │ OUTBOUND_EXTERNAL (Agent → Cloud Relay)                      │
└─────────────────┼──────────────────────────────────────────────────────────────┘
                  │
                  ▼
┌─────────────────────────────────────────────────────────────────────────────────┐
│                    CLOUD RELAY (External - VM/Cloud/On-Prem)                     │
│                    SELF-CONTAINED Attack Infrastructure                          │
│                                                                                  │
│  ┌─────────────────────────────────────────────────────────────────────────┐   │
│  │  OUTBOUND Attack Reception          │  INBOUND Attack Execution         │   │
│  │  (Receives callbacks from agents)   │  (Attacks targets from outside)   │   │
│  │  ┌─────────────┐  ┌─────────────┐   │  ┌─────────────┐  ┌─────────────┐ │   │
│  │  │  HTTP C2    │  │  DNS C2     │   │  │ WAF Tester  │  │ Web Scanner │ │   │
│  │  │  /beacon    │  │  dns.relay  │   │  │ SQLi, XSS   │  │ Vuln Scan   │ │   │
│  │  │  /exfil     │  │             │   │  │ RCE, LFI    │  │             │ │   │
│  │  │  /stage     │  │             │   │  │ SSRF, XXE   │  │             │ │   │
│  │  └─────────────┘  └─────────────┘   │  └─────────────┘  └─────────────┘ │   │
│  │  ┌─────────────┐  ┌─────────────┐   │  ┌─────────────┐                   │   │
│  │  │ SMTP Phish  │  │ File Exfil  │   │  │ Port Scan   │                   │   │
│  │  │ /phishing   │  │ Upload recv │   │  │ Service Enum│                   │   │
│  │  └─────────────┘  └─────────────┘   │  └─────────────┘                   │   │
│  └─────────────────────────────────────────────────────────────────────────┘   │
│                                                                                  │
│  Key: Cloud Relay is SELF-CONTAINED - handles attacks INDEPENDENTLY             │
│       Master Server queries Cloud Relay API for execution results               │
└─────────────────────────────────────────────────────────────────────────────────┘
```

## Execution Models

| Model | Direction | Description |
|-------|-----------|-------------|
| **OUTBOUND_EXTERNAL** | Agent → Cloud Relay | C2 callbacks, data exfiltration |
| **INBOUND_EXTERNAL** | Cloud Relay → Target | WAF testing, web attacks, port scanning |

## Cloud Agnostic Design

Deploy on **any Kubernetes cluster** or serverless platform:

| Provider | Recommended Service | Region |
|----------|---------------------|--------|
| **GCP** | GKE / Cloud Run | me-central2 (Saudi Arabia) |
| **AWS** | EKS / Fargate | me-south-1 (Bahrain) |
| **Azure** | AKS / Container Apps | UAE North |
| **On-Prem** | K3s / Docker | Air-gapped environments |

## Key Features

- **Self-Contained**: All attack capabilities built-in, no external dependencies
- **Real Traffic**: Handles actual C2 callbacks and attack execution - not simulations
- **Cloud Agnostic**: Deploy on GCP, AWS, Azure, or on-prem
- **Multi-Tenant**: Isolated namespaces per customer
- **Scales to Zero**: Serverless options for cost optimization
- **Full Audit Trail**: All activity logged for evidence collection

## Services & MITRE ATT&CK Coverage

### OUTBOUND Services (Receive callbacks from agents)

| Service | Endpoints | MITRE Techniques |
|---------|-----------|------------------|
| **HTTP C2** | `/beacon`, `/exfil`, `/stage`, `/download` | T1071.001 (Web Protocols), T1041 (Exfiltration Over C2) |
| **DNS C2** | DNS queries to relay domain | T1071.004 (DNS), T1568.002 (Domain Generation) |
| **SMTP Phishing** | `/phishing`, `/track`, `/landing` | T1566.002 (Spearphishing Link), T1598 (Phishing for Info) |
| **File Exfil** | Upload endpoint | T1048 (Exfiltration Over Alternative Protocol) |

### INBOUND Services (Attack targets from Cloud Relay)

| Service | Attack Types | MITRE Techniques |
|---------|--------------|------------------|
| **WAF Tester** | SQLi, XSS, RCE, LFI, RFI, SSRF, XXE, SSTI | T1190 (Exploit Public-Facing App) |
| **Web Scanner** | Vulnerability scanning | T1595 (Active Scanning) |
| **Port Scanner** | Service enumeration | T1046 (Network Service Scanning) |

## Directory Structure

```
mirqab-cloud-relay/
├── README.md
├── docker-compose.yml           # Local/VM deployment
├── kubernetes/
│   ├── base/                    # Cloud-agnostic base configs
│   └── overlays/
│       ├── gcp/                 # GCP-specific
│       ├── aws/                 # AWS-specific
│       └── local/               # Local K3s/Kind
├── services/
│   ├── http-c2/                 # HTTP C2 service (beacon, exfil, staging)
│   ├── smtp-phishing/           # SMTP phishing service
│   ├── waf-tester/              # WAF testing service (INBOUND attacks)
│   ├── dns-c2/                  # DNS C2 service (TODO)
│   └── file-exfil/              # File exfiltration service (TODO)
├── terraform/
│   ├── gcp/                     # GCP infrastructure
│   └── aws/                     # AWS infrastructure (TODO)
├── helm/                        # Helm chart (TODO)
└── docs/
```

## Implementation Status

### OUTBOUND Services (Receive C2 callbacks)
- [x] **HTTP C2 Service** - Beacon callbacks, payload staging, exfiltration
- [x] **SMTP Phishing Service** - Campaign tracking, landing pages
- [ ] **DNS C2 Service** - DNS tunneling (TODO)
- [ ] **File Exfiltration Service** - Cloud storage abstraction (TODO)

### INBOUND Services (Attack targets)
- [x] **DVWA Target** - Vulnerable web app for WAF testing
- [ ] **WAF Tester Service** - Automated attack execution (TODO)
- [ ] **Web Scanner Service** - Vulnerability scanning (TODO)

### Infrastructure
- [x] Docker Compose deployment
- [x] Traefik reverse proxy with routing
- [x] Multi-tenant namespace isolation (design)
- [ ] Kubernetes manifests (TODO)
- [ ] Terraform modules (GCP done, AWS/Azure TODO)

### Security
- [x] HMAC request authentication
- [x] Audit logging
- [ ] mTLS with Master Server (TODO)
- [ ] Rate limiting (TODO)

## Quick Start

### Local Development (K3d/Kind)
```bash
# Create local cluster
k3d cluster create mirqab-relay

# Deploy
kubectl apply -k kubernetes/overlays/local
```

### GCP Deployment
```bash
cd terraform/gcp
terraform init && terraform apply
kubectl apply -k kubernetes/overlays/gcp
```

### AWS Deployment
```bash
cd terraform/aws
terraform init && terraform apply
kubectl apply -k kubernetes/overlays/aws
```

## Security Model

1. **Tenant Isolation**: NetworkPolicies + separate namespaces
2. **HMAC Authentication**: Signed requests from authorized agents only
3. **mTLS**: Optional mutual TLS with Master Server for results API
4. **Rate Limiting**: Per-tenant limits to prevent abuse
5. **Audit Logging**: All C2 activity logged for evidence
6. **Geo-Fencing**: Optional IP restrictions per tenant

## Cost Optimization

- Serverless options scale to zero
- Auto-delete test data after 7 days
- Budget alerts at configurable thresholds
