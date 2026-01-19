# Mirqab Cloud Relay - Observability Stack

This directory contains the configuration for the Cloud Relay observability stack, including Prometheus, Grafana, Loki, and Alertmanager.

## Components

| Component | Purpose | Location |
|-----------|---------|----------|
| **Prometheus** | Metrics collection and alerting | `prometheus/` |
| **Grafana** | Dashboards and visualization | `grafana/` |
| **Loki** | Log aggregation | `loki/` |
| **Alertmanager** | Alert routing and notification | `alertmanager/` |

## Installation

### Prerequisites

- Kubernetes cluster (EKS) with Cloud Relay installed
- Helm 3.x
- kubectl configured for the cluster

### Step 1: Add Helm Repositories

```bash
helm repo add prometheus-community https://prometheus-community.github.io/helm-charts
helm repo add grafana https://grafana.github.io/helm-charts
helm repo update
```

### Step 2: Create Namespaces

```bash
kubectl create namespace monitoring
kubectl create namespace logging
```

### Step 3: Deploy Prometheus Stack

```bash
# Create secrets first
kubectl create secret generic grafana-admin-secret \
  --namespace monitoring \
  --from-literal=admin-password='your-secure-password'

# Install kube-prometheus-stack
helm install prometheus prometheus-community/kube-prometheus-stack \
  --namespace monitoring \
  --values prometheus/prometheus-stack.yaml
```

### Step 4: Deploy Loki Stack

```bash
# Install Loki with Promtail
helm install loki grafana/loki-stack \
  --namespace logging \
  --values loki/loki-stack.yaml
```

### Step 5: Import Dashboards

```bash
# Create ConfigMap for dashboard
kubectl create configmap mirqab-overview-dashboard \
  --namespace monitoring \
  --from-file=grafana/dashboards/mirqab-overview.json \
  --dry-run=client -o yaml | \
  kubectl label --local -f - grafana_dashboard=1 -o yaml | \
  kubectl apply -f -
```

### Step 6: Configure Alertmanager

```bash
# Create alertmanager secrets (replace with actual values)
kubectl create secret generic alertmanager-secrets \
  --namespace monitoring \
  --from-literal=SMTP_USERNAME='your-smtp-user' \
  --from-literal=SMTP_PASSWORD='your-smtp-password' \
  --from-literal=SLACK_WEBHOOK_URL='https://hooks.slack.com/...' \
  --from-literal=PAGERDUTY_SERVICE_KEY='your-pd-key' \
  --from-literal=COMMAND_CENTER_TOKEN='your-cc-token'

# Apply alertmanager config
kubectl apply -f alertmanager/alertmanager-config.yaml
```

## Accessing Services

### Grafana

```bash
# Port forward
kubectl port-forward svc/prometheus-grafana 3000:80 -n monitoring

# Or via Ingress (if configured)
# https://grafana.mirqab.io
```

Default credentials:
- Username: `admin`
- Password: (from secret or values.yaml)

### Prometheus

```bash
kubectl port-forward svc/prometheus-kube-prometheus-prometheus 9090:9090 -n monitoring
```

### Alertmanager

```bash
kubectl port-forward svc/prometheus-kube-prometheus-alertmanager 9093:9093 -n monitoring
```

## Dashboards

### Mirqab Cloud Relay - Overview

Main dashboard showing:
- Active tenant count
- Channel usage across all tenants
- Total active C2 sessions
- Storage usage
- Beacon rate by tenant
- Tenant distribution by tier
- Detailed tenant table

### Tenant-Specific Dashboards

Each tenant can view their own metrics via filtered dashboards using the `tenant_id` variable.

## Alerts

### Critical Alerts

| Alert | Description | Severity |
|-------|-------------|----------|
| `TenantC2HttpDown` | C2 HTTP service down for >5min | Critical |
| `TenantC2DnsDown` | C2 DNS service down for >5min | Critical |
| `PayloadStorageFull` | Storage >95% capacity | Critical |
| `LicenseExpired` | Tenant license has expired | Critical |
| `OperatorDown` | Mirqab operator is down | Critical |

### Warning Alerts

| Alert | Description | Severity |
|-------|-------------|----------|
| `TenantPayloadServerDown` | Payload server down for >5min | Warning |
| `HighBeaconErrorRate` | Error rate >10% | Warning |
| `PayloadStorageNearLimit` | Storage >80% capacity | Warning |
| `LicenseExpiringSoon` | License expires in <7 days | Warning |
| `TenantProvisioningFailed` | Provisioning failures detected | Warning |

### Info Alerts

| Alert | Description | Severity |
|-------|-------------|----------|
| `NoBeaconActivity` | No beacons for 2+ hours | Info |

## Metrics Reference

### C2 HTTP Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `mirqab_c2_http_beacons_total` | Counter | Total beacon check-ins |
| `mirqab_c2_http_beacon_errors_total` | Counter | Beacon errors |
| `mirqab_c2_http_active_sessions` | Gauge | Current active sessions |
| `mirqab_c2_http_commands_sent_total` | Counter | Commands dispatched |
| `mirqab_c2_http_request_duration_seconds` | Histogram | Request latency |

### C2 DNS Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `mirqab_c2_dns_queries_total` | Counter | Total DNS queries |
| `mirqab_c2_dns_tunnel_bytes_total` | Counter | Data tunneled via DNS |
| `mirqab_c2_dns_active_sessions` | Gauge | Active DNS tunnel sessions |

### Payload Server Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `mirqab_payload_uploads_total` | Counter | Total uploads |
| `mirqab_payload_downloads_total` | Counter | Total downloads |
| `mirqab_payload_storage_used_bytes` | Gauge | Storage used |
| `mirqab_payload_storage_limit_bytes` | Gauge | Storage limit |

### Operator Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `mirqab_operator_reconcile_total` | Counter | Total reconciliations |
| `mirqab_operator_reconcile_duration_seconds` | Histogram | Reconcile latency |
| `mirqab_operator_tenant_provisioning_failures_total` | Counter | Provisioning failures |
| `mirqab_tenant_info` | Gauge | Tenant metadata (labels) |

## Log Queries (LogQL)

### Find errors for a specific tenant

```logql
{namespace=~"tenant-.*", tenant_id="your-tenant-id"} |= "error"
```

### Beacon activity

```logql
{component="c2-service"} |~ "beacon" | json | line_format "{{.agent_id}}: {{.msg}}"
```

### Failed downloads

```logql
{component="payload-service"} |= "download" |= "failed"
```

## Maintenance

### Scaling Prometheus

```bash
# Increase replicas
kubectl patch prometheus prometheus-kube-prometheus-prometheus \
  --namespace monitoring \
  --type='json' \
  -p='[{"op": "replace", "path": "/spec/replicas", "value": 3}]'
```

### Backup Grafana Dashboards

```bash
# Export all dashboards
for uid in $(kubectl exec -n monitoring deployment/prometheus-grafana -- \
  curl -s localhost:3000/api/search | jq -r '.[].uid'); do
  kubectl exec -n monitoring deployment/prometheus-grafana -- \
    curl -s localhost:3000/api/dashboards/uid/$uid > dashboard-$uid.json
done
```

### Retention Cleanup

Prometheus retention is configured in `prometheus-stack.yaml`:
- `retention: 30d` - Keep metrics for 30 days
- `retentionSize: 50GB` - Maximum storage size

Loki retention is configured in `loki-stack.yaml`:
- `retention_period: 720h` - Keep logs for 30 days
