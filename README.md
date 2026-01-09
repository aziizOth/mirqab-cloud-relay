# Mirqab Cloud Relay

**Phase 2B: Cloud-Agnostic C2 Infrastructure**

Multi-tenant infrastructure for Command & Control (C2) channels during security validation exercises.
Handles **REAL** attack traffic from OffenSight agents - not simulations.

## Cloud Agnostic Design

This relay is designed to run on **any Kubernetes cluster** or serverless platform:

| Provider | Recommended Service | Region |
|----------|---------------------|--------|
| **GCP** | GKE / Cloud Run | me-central2 (Saudi Arabia) |
| **AWS** | EKS / Fargate | me-south-1 (Bahrain) |
| **Azure** | AKS / Container Apps | UAE North |
| **On-Prem** | K3s / K8s | Air-gapped environments |

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                      Any Kubernetes Cluster                             │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │                    Tenant Namespace Isolation                      │  │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────────┐   │  │
│  │  │  HTTP C2    │  │  DNS C2     │  │  File Exfil Service     │   │  │
│  │  │  Service    │  │  Service    │  │  (S3/GCS/Azure/MinIO)   │   │  │
│  │  └──────┬──────┘  └──────┬──────┘  └───────────┬─────────────┘   │  │
│  │         │                │                      │                  │  │
│  │         └────────────────┼──────────────────────┘                  │  │
│  │                          │                                          │  │
│  │                    ┌─────┴─────┐                                    │  │
│  │                    │  Ingress  │                                    │  │
│  │                    │  Gateway  │                                    │  │
│  │                    └─────┬─────┘                                    │  │
│  └──────────────────────────┼───────────────────────────────────────┘  │
│                             │                                           │
│                    Network Policies                                     │
│                    + Rate Limiting                                      │
└─────────────────────────────┼───────────────────────────────────────────┘
                              │
                    ┌─────────┴─────────┐
                    │  Customer Agents  │
                    │  (OffenSight)     │
                    └───────────────────┘
```

## Key Features

- **Real C2 Traffic**: Receives actual attack callbacks from agents
- **Cloud Agnostic**: Deploy on GCP, AWS, Azure, or on-prem
- **Multi-Tenant**: Isolated namespaces per customer
- **Scales to Zero**: No cost when not in use
- **mTLS**: Mutual TLS authentication with Command Center

## Directory Structure

```
mirqab-cloud-relay/
├── README.md
├── kubernetes/
│   ├── base/                    # Cloud-agnostic base configs
│   │   ├── namespace.yaml
│   │   ├── network-policy.yaml
│   │   ├── deployments/
│   │   └── services/
│   └── overlays/
│       ├── gcp/                 # GCP-specific
│       ├── aws/                 # AWS-specific
│       ├── azure/               # Azure-specific
│       └── local/               # Local K3s/Kind
├── services/
│   ├── http-c2/                 # HTTP C2 service
│   ├── dns-c2/                  # DNS C2 service
│   └── file-exfil/              # File exfiltration service
├── terraform/
│   ├── gcp/                     # GCP infrastructure
│   ├── aws/                     # AWS infrastructure (TODO)
│   └── azure/                   # Azure infrastructure (TODO)
├── helm/                        # Helm chart
└── docs/
```

## Sprint Plan

### Sprint 23: Infrastructure Foundation
- [x] Project structure
- [x] Cloud-agnostic Kubernetes base
- [x] Terraform GCP setup
- [ ] Terraform AWS/Azure (when needed)
- [ ] Network policies

### Sprint 24: HTTP C2 Service
- [x] HTTP beacon handler
- [x] Payload staging
- [x] Exfiltration endpoint
- [ ] Kubernetes deployment manifests

### Sprint 25: DNS C2 Service
- [ ] DNS tunneling handler
- [ ] CoreDNS integration

### Sprint 26: File Exfiltration
- [ ] Cloud storage abstraction (S3/GCS/Azure/MinIO)
- [ ] Chunked uploads

### Sprint 27: Gateway & Security
- [ ] Ingress with TLS
- [ ] mTLS with Command Center

### Sprint 28: Observability
- [ ] Prometheus metrics
- [ ] Grafana dashboards

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
2. **mTLS**: Authenticated traffic with Command Center
3. **Rate Limiting**: Per-tenant limits
4. **Audit Logging**: All C2 activity logged
5. **Geo-Fencing**: Optional IP restrictions

## Cost Optimization

- Serverless options scale to zero
- Auto-delete test data after 7 days
- Budget alerts at configurable thresholds
