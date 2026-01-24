#!/bin/bash
set -e

# Deploy Mirqab Cloud Relay to target VM
# Usage: ./deploy-to-vm.sh <target-ip> [user] [password]

TARGET_IP="${1:-192.168.100.67}"
TARGET_USER="${2:-relay}"
TARGET_PASS="${3:-relay@123\$}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

echo "============================================"
echo "  Deploying Mirqab Cloud Relay"
echo "============================================"
echo "Target: $TARGET_USER@$TARGET_IP"
echo "Source: $PROJECT_DIR"
echo ""

# Check if sshpass is available
if ! command -v sshpass &> /dev/null; then
    echo "Installing sshpass..."
    sudo apt-get update && sudo apt-get install -y sshpass
fi

SSH_CMD="sshpass -p '$TARGET_PASS' ssh -o StrictHostKeyChecking=no $TARGET_USER@$TARGET_IP"
SCP_CMD="sshpass -p '$TARGET_PASS' scp -o StrictHostKeyChecking=no"

echo "[1/5] Testing connectivity..."
eval "$SSH_CMD" "echo 'Connection successful'"

echo "[2/5] Running installation script on target..."
eval "$SCP_CMD" "$SCRIPT_DIR/install.sh" "$TARGET_USER@$TARGET_IP:/tmp/"
eval "$SSH_CMD" "sudo bash /tmp/install.sh"

echo "[3/5] Copying project files..."
# Create a tarball for faster transfer
TEMP_TAR="/tmp/mirqab-cloud-relay-deploy.tar.gz"
cd "$PROJECT_DIR"
tar -czf "$TEMP_TAR" \
    --exclude='.git' \
    --exclude='__pycache__' \
    --exclude='.pytest_cache' \
    --exclude='*.pyc' \
    --exclude='node_modules' \
    --exclude='.venv' \
    services docker-compose.yml helm kubernetes observability sdk

eval "$SCP_CMD" "$TEMP_TAR" "$TARGET_USER@$TARGET_IP:/tmp/"
eval "$SSH_CMD" "sudo tar -xzf /tmp/mirqab-cloud-relay-deploy.tar.gz -C /opt/mirqab/cloud-relay/"
rm -f "$TEMP_TAR"

echo "[4/5] Configuring environment..."
eval "$SSH_CMD" "sudo cp /etc/mirqab/cloud-relay.env.template /etc/mirqab/cloud-relay.env"

# Generate random passwords
DB_PASS=$(openssl rand -base64 16 | tr -dc 'a-zA-Z0-9' | head -c 16)
ADMIN_TOKEN=$(openssl rand -base64 32 | tr -dc 'a-zA-Z0-9' | head -c 32)
SECRET_KEY=$(openssl rand -base64 32 | tr -dc 'a-zA-Z0-9' | head -c 32)

eval "$SSH_CMD" "sudo sed -i 's/POSTGRES_PASSWORD=CHANGE_ME/POSTGRES_PASSWORD=$DB_PASS/g' /etc/mirqab/cloud-relay.env"
eval "$SSH_CMD" "sudo sed -i 's/ADMIN_TOKEN=CHANGE_ME/ADMIN_TOKEN=$ADMIN_TOKEN/g' /etc/mirqab/cloud-relay.env"
eval "$SSH_CMD" "sudo sed -i 's/SECRET_KEY=CHANGE_ME/SECRET_KEY=$SECRET_KEY/g' /etc/mirqab/cloud-relay.env"
eval "$SSH_CMD" "sudo sed -i 's|DATABASE_URL=postgresql://relay:CHANGE_ME|DATABASE_URL=postgresql://relay:$DB_PASS|g' /etc/mirqab/cloud-relay.env"

echo "[5/5] Starting services..."
eval "$SSH_CMD" "cd /opt/mirqab/cloud-relay && sudo docker compose up -d"

echo ""
echo "============================================"
echo "  Deployment Complete!"
echo "============================================"
echo ""
echo "Services should be starting. Check status with:"
echo "  ssh $TARGET_USER@$TARGET_IP 'docker ps'"
echo ""
echo "API Gateway: http://$TARGET_IP:8000"
echo "HTTP C2:     http://$TARGET_IP:8080"
echo "Grafana:     http://$TARGET_IP:3000 (admin/mirqab)"
echo ""
echo "Credentials saved to /etc/mirqab/cloud-relay.env on target"
echo ""
