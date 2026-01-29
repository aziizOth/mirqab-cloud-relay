# Changelog

All notable changes to the Mirqab Cloud Relay project will be documented in this file.

## [1.3.0] - 2026-01-29

### Phase 3: Monitoring, CI/CD & Backup

#### Monitoring (Prometheus + Grafana)
- Added 8 custom Prometheus metrics to API Gateway (request count, duration, active requests, auth failures, rate limit hits, quota exceeded, proxy errors, proxy duration)
- Created `docker-compose.monitoring.yml` overlay with Prometheus v2.51.0 + Grafana 10.4.0
- Added 7 Prometheus alert rules (GatewayDown, HighErrorRate, HighLatencyP95, RateLimitSpike, AuthFailureSpike, BackendProxyErrors, TraefikDown)
- Auto-provisioned Grafana dashboards: API Gateway + Cloud Relay Overview
- Enabled Traefik Prometheus metrics export

#### CI/CD Pipelines (GitHub Actions)
- `.github/workflows/ci.yml` — lint (ruff + staticcheck), test (pytest + Go), build (6-service matrix), security scan (hardening + Trivy)
- `.github/workflows/deploy-vm.yml` — manual SSH deploy with health checks
- `.github/workflows/build-images.yml` — build + push to ghcr.io on version tags

#### Backup Automation
- `scripts/backup.sh` — PostgreSQL dumps, Docker volume tarballs, config archive, 30-day retention
- `scripts/restore.sh` — interactive restore with safety confirmation
- `scripts/install-backup-cron.sh` — daily 2 AM cron installer
- Makefile targets: `backup`, `restore`, `install-backup-cron`

### Files Added
- `services/api-gateway/metrics.py`
- `docker-compose.monitoring.yml`
- `monitoring/prometheus/prometheus.yml`
- `monitoring/prometheus/alerts.yml`
- `monitoring/grafana/` (provisioning configs + dashboards)
- `.github/workflows/ci.yml`
- `.github/workflows/deploy-vm.yml`
- `.github/workflows/build-images.yml`
- `scripts/backup.sh`
- `scripts/restore.sh`
- `scripts/install-backup-cron.sh`

---

## [1.2.0] - 2026-01-27

### Phase 2: Production Hardening

- Externalized all secrets via `scripts/generate-secrets.sh` (16 vars in `.env`)
- TLS 1.3 enforced on Traefik with `scripts/generate-tls-certs.sh`
- Redis authentication enabled with generated password
- Docker network isolation (no inter-service crosstalk)
- 12-point hardening validation script (`scripts/validate-hardening.sh`)
- No hardcoded credentials in source code
- `.gitignore` updated for secrets, keys, certs

---

## [1.1.0] - 2026-01-25

### Phase 1.5: API Gateway & Security Middleware

- Built API Gateway (FastAPI) with full security middleware stack
- API key authentication with tenant resolution
- Per-tenant rate limiting (Redis-backed, sliding window)
- Quota enforcement per feature (tasks, scans, exports)
- mTLS certificate validation
- Request signing (HMAC-SHA256) with nonce/timestamp replay protection
- Reverse proxy forwarding to backend services via Traefik
- Health endpoint (`/health`) with dependency checks
- Audit logging with tenant context
- Integration tested with OffenSight (outbound 19/19, inbound 32/32)

---

## [1.0.0] - 2026-01-21

### Initial Deployment

- Initial deployment to Cloud Relay VM (192.168.100.67)
- Docker Compose stack with 5 services operational

| Service | Container | Port | Status |
|---------|-----------|------|--------|
| Traefik (Reverse Proxy) | relay-traefik | 80, 587, 8080 | Running |
| HTTP C2 | relay-http-c2 | 8080 (internal) | Healthy |
| SMTP Phishing | relay-smtp-phishing | 8081 (internal) | Healthy |
| Redis | relay-redis | 6379 (internal) | Healthy |
| MailHog (SMTP Testing) | relay-mailhog | 1025, 8025 | Running |

### Infrastructure
- **VM**: 192.168.100.67, Ubuntu 24.04.3 LTS
- **Docker**: v28.2.2
- Deployment scripts: `deploy/install.sh`, `deploy/deploy-to-vm.sh`, `deploy/deploy-to-gcp.sh`

---

## Pending

- [ ] WAF rules (deferred to cloud migration)
- [ ] DDoS protection (deferred to cloud migration)
- [ ] Kubernetes resource quotas (deferred to cloud migration)
- [ ] DR plan documentation
- [ ] Runbooks
- [ ] Load testing
- [ ] Security audit
- [ ] GCP/cloud migration
