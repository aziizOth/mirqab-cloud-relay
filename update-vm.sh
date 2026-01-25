#!/bin/bash
# Update Cloud Relay VM with latest docker-compose
# Run this script manually: ./update-vm.sh

VM_HOST="192.168.100.67"
VM_USER="relay"
REMOTE_PATH="/home/relay/mirqab-cloud-relay"

echo "=== Updating Cloud Relay VM ($VM_HOST) ==="
echo ""

# Copy docker-compose.yml
echo "1. Copying docker-compose.yml..."
scp docker-compose.yml ${VM_USER}@${VM_HOST}:${REMOTE_PATH}/

# Copy service directories
echo "2. Copying services..."
scp -r services/http-c2 ${VM_USER}@${VM_HOST}:${REMOTE_PATH}/services/
scp -r services/smtp-phishing ${VM_USER}@${VM_HOST}:${REMOTE_PATH}/services/
scp -r services/waf-tester ${VM_USER}@${VM_HOST}:${REMOTE_PATH}/services/
scp -r services/payload-service ${VM_USER}@${VM_HOST}:${REMOTE_PATH}/services/
scp -r services/c2-gateway ${VM_USER}@${VM_HOST}:${REMOTE_PATH}/services/
scp -r services/sliver ${VM_USER}@${VM_HOST}:${REMOTE_PATH}/services/

# SSH and restart services
echo "3. Restarting Docker services on VM..."
ssh ${VM_USER}@${VM_HOST} << 'EOF'
cd /home/relay/mirqab-cloud-relay
docker compose down
docker compose up -d --build
sleep 30
docker ps --format "table {{.Names}}\t{{.Status}}"
echo ""
echo "Checking Traefik routes..."
curl -s http://localhost:8080/api/http/routers | jq -r '.[] | "\(.name): \(.rule)"' 2>/dev/null || echo "Traefik API not available"
echo ""
echo "Testing payload service..."
curl -s http://localhost/payloads | head -c 200
EOF

echo ""
echo "=== Done! ==="
echo "Test with:"
echo "  curl http://${VM_HOST}/beacon -X POST -d '{}'"
echo "  curl http://${VM_HOST}/payloads"
echo "  curl http://${VM_HOST}/download/eicar.exe"
