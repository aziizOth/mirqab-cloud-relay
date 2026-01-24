#!/bin/bash
set -e

# Mirqab Cloud Relay - Installation Script
# Target: Ubuntu 22.04 LTS

INSTALL_DIR="/opt/mirqab/cloud-relay"
CONFIG_DIR="/etc/mirqab"
LOG_DIR="/var/log/mirqab"
DATA_DIR="/var/lib/mirqab"

echo "============================================"
echo "  Mirqab Cloud Relay Installation Script"
echo "============================================"

# Check if running as root or with sudo
if [ "$EUID" -ne 0 ]; then
    echo "Please run with sudo or as root"
    exit 1
fi

# Detect OS
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$ID
    VERSION=$VERSION_ID
else
    echo "Cannot detect OS. Exiting."
    exit 1
fi

echo "[1/8] Updating system packages..."
apt-get update -qq
apt-get upgrade -y -qq

echo "[2/8] Installing dependencies..."
apt-get install -y -qq \
    apt-transport-https \
    ca-certificates \
    curl \
    gnupg \
    lsb-release \
    git \
    python3 \
    python3-pip \
    python3-venv \
    jq

echo "[3/8] Installing Docker..."
if ! command -v docker &> /dev/null; then
    curl -fsSL https://get.docker.com -o get-docker.sh
    sh get-docker.sh
    rm get-docker.sh
    systemctl enable docker
    systemctl start docker
else
    echo "Docker already installed"
fi

# Install Docker Compose plugin
if ! docker compose version &> /dev/null; then
    apt-get install -y -qq docker-compose-plugin
fi

echo "[4/8] Creating directories..."
mkdir -p $INSTALL_DIR
mkdir -p $CONFIG_DIR/certs
mkdir -p $LOG_DIR
mkdir -p $DATA_DIR/postgresql
mkdir -p $DATA_DIR/redis
mkdir -p $DATA_DIR/payloads
mkdir -p $DATA_DIR/exfil

echo "[5/8] Setting permissions..."
# Create mirqab user if not exists
if ! id "mirqab" &>/dev/null; then
    useradd -r -s /bin/false mirqab
fi
usermod -aG docker mirqab 2>/dev/null || true
chown -R mirqab:mirqab $INSTALL_DIR $CONFIG_DIR $LOG_DIR $DATA_DIR

echo "[6/8] Creating environment template..."
cat > $CONFIG_DIR/cloud-relay.env.template << 'EOF'
# Mirqab Cloud Relay Configuration
# Copy to /etc/mirqab/cloud-relay.env and fill in values

# Core Settings
ENVIRONMENT=prod
NODE_ENV=production

# Command Center Integration
COMMAND_CENTER_URL=https://command.mirqab.io
SIGNING_KEY=

# Database
DATABASE_URL=postgresql://relay:CHANGE_ME@localhost:5432/cloud_relay
POSTGRES_USER=relay
POSTGRES_PASSWORD=CHANGE_ME
POSTGRES_DB=cloud_relay

# Redis
REDIS_URL=redis://localhost:6379

# Multi-tenant
MULTI_TENANT_ENABLED=true
TENANT_ISOLATION_MODE=strict

# Security
ADMIN_TOKEN=CHANGE_ME
SECRET_KEY=CHANGE_ME

# TLS (optional - enable for production)
TLS_ENABLED=false
TLS_CERT_PATH=/etc/mirqab/certs/server.crt
TLS_KEY_PATH=/etc/mirqab/certs/server.key

# Storage
STORAGE_BACKEND=local
LOCAL_STORAGE_PATH=/var/lib/mirqab/payloads

# Service Ports
API_GATEWAY_PORT=8000
HTTP_C2_PORT=8080
DNS_C2_PORT=5353
EXFIL_PORT=8081
PAYLOAD_PORT=8083
METRICS_PORT=9090

# Observability
PROMETHEUS_ENABLED=true
GRAFANA_ENABLED=true
LOKI_ENABLED=true
EOF

echo "[7/8] Creating systemd service..."
cat > /etc/systemd/system/mirqab-cloud-relay.service << EOF
[Unit]
Description=Mirqab Cloud Relay
Requires=docker.service
After=docker.service network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
WorkingDirectory=$INSTALL_DIR
EnvironmentFile=$CONFIG_DIR/cloud-relay.env
ExecStart=/usr/bin/docker compose -f docker-compose.yml up -d
ExecStop=/usr/bin/docker compose -f docker-compose.yml down
ExecReload=/usr/bin/docker compose -f docker-compose.yml restart

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload

echo "[8/8] Installation complete!"
echo ""
echo "============================================"
echo "  Next Steps:"
echo "============================================"
echo ""
echo "1. Copy project files to: $INSTALL_DIR"
echo "   rsync -avz ./services ./docker-compose.yml $INSTALL_DIR/"
echo ""
echo "2. Configure environment:"
echo "   sudo cp $CONFIG_DIR/cloud-relay.env.template $CONFIG_DIR/cloud-relay.env"
echo "   sudo nano $CONFIG_DIR/cloud-relay.env"
echo ""
echo "3. Start services:"
echo "   sudo systemctl enable mirqab-cloud-relay"
echo "   sudo systemctl start mirqab-cloud-relay"
echo ""
echo "4. Check status:"
echo "   sudo systemctl status mirqab-cloud-relay"
echo "   docker compose -f $INSTALL_DIR/docker-compose.yml ps"
echo ""
echo "============================================"
