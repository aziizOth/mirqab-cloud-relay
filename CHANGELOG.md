# Changelog

All notable changes to the Mirqab Cloud Relay project will be documented in this file.

## [1.0.0] - 2026-01-21

### Deployed
- Initial deployment to Cloud Relay VM (192.168.100.67)
- Docker Compose stack with 5 services operational

### Services Running
| Service | Container | Port | Status |
|---------|-----------|------|--------|
| Traefik (Reverse Proxy) | relay-traefik | 80, 587, 8080 | Running |
| HTTP C2 | relay-http-c2 | 8080 (internal) | Healthy |
| SMTP Phishing | relay-smtp-phishing | 8081 (internal) | Healthy |
| Redis | relay-redis | 6379 (internal) | Healthy |
| MailHog (SMTP Testing) | relay-mailhog | 1025, 8025 | Running |

### Configuration
- Environment: Production mode
- Database: PostgreSQL (relay:RelaySecure2026)
- Redis: redis://redis:6379
- Multi-tenant: Enabled with strict isolation
- TLS: Disabled (pending certificate setup)

### Infrastructure
- **VM IP**: 192.168.100.67
- **OS**: Ubuntu 24.04.3 LTS
- **Docker**: v28.2.2
- **Kernel**: 6.8.0-90-generic

### Files Created
- `/opt/mirqab/cloud-relay/` - Main deployment directory
- `/opt/mirqab/cloud-relay/.env` - Environment configuration
- `/opt/mirqab/cloud-relay/docker-compose.yml` - Service definitions
- `/opt/mirqab/cloud-relay/services/` - Microservices source
- `/etc/mirqab/` - System configuration directory
- `/var/log/mirqab/` - Log directory
- `/var/lib/mirqab/` - Data directory

### Access Credentials
- **SSH**: relay@192.168.100.67 (relay@123$)
- **Admin Token**: mirqab-admin-token-2026
- **Grafana**: admin/mirqab (when enabled)

### Deployment Scripts Added
- `deploy/install.sh` - VM setup automation
- `deploy/deploy-to-vm.sh` - Remote deployment script
- `deploy/deploy-to-gcp.sh` - GCP deployment automation
- `deploy/create-package.sh` - Package creation utility

---

## Pending Tasks

### Phase 2: Production Hardening
- [ ] Configure TLS certificates
- [ ] Set up DNS records
- [ ] Enable Cloud Armor/WAF
- [ ] Configure monitoring alerts

### Phase 3: GCP Migration
- [ ] Deploy to GCP (GKE/Cloud Run/VM)
- [ ] Configure Cloud SQL
- [ ] Set up Cloud DNS
- [ ] Enable Cloud Monitoring

### Phase 4: Integration
- [ ] Connect to Command Center
- [ ] Configure mTLS certificates
- [ ] Test tenant provisioning
- [ ] Validate C2 channels
