#!/bin/bash
set -e

# Create deployment package for Mirqab Cloud Relay
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
PACKAGE_NAME="mirqab-cloud-relay-$(date +%Y%m%d)"
OUTPUT_DIR="${1:-/tmp}"
PACKAGE_PATH="$OUTPUT_DIR/$PACKAGE_NAME"

echo "============================================"
echo "  Creating Mirqab Cloud Relay Package"
echo "============================================"
echo "Source: $PROJECT_DIR"
echo "Output: $PACKAGE_PATH"
echo ""

# Clean up any existing package
rm -rf "$PACKAGE_PATH" "$PACKAGE_PATH.tar.gz"
mkdir -p "$PACKAGE_PATH"

echo "[1/6] Copying services..."
cp -r "$PROJECT_DIR/services" "$PACKAGE_PATH/"

echo "[2/6] Copying Docker Compose..."
cp "$PROJECT_DIR/docker-compose.yml" "$PACKAGE_PATH/"

echo "[3/6] Copying Kubernetes manifests..."
cp -r "$PROJECT_DIR/kubernetes" "$PACKAGE_PATH/"

echo "[4/6] Copying Helm chart..."
cp -r "$PROJECT_DIR/helm" "$PACKAGE_PATH/"

echo "[5/6] Copying deployment scripts..."
mkdir -p "$PACKAGE_PATH/deploy"
cp "$SCRIPT_DIR/install.sh" "$PACKAGE_PATH/deploy/"
cp "$SCRIPT_DIR/deploy-to-vm.sh" "$PACKAGE_PATH/deploy/" 2>/dev/null || true

# Create README
cat > "$PACKAGE_PATH/README.md" << 'EOF'
# Mirqab Cloud Relay - Deployment Package

## Quick Start

### Option 1: Docker Compose (Recommended for single VM)

```bash
# 1. Run installation script
sudo ./deploy/install.sh

# 2. Copy files to /opt/mirqab/cloud-relay
sudo cp -r services docker-compose.yml /opt/mirqab/cloud-relay/

# 3. Configure environment
sudo cp /etc/mirqab/cloud-relay.env.template /etc/mirqab/cloud-relay.env
sudo nano /etc/mirqab/cloud-relay.env

# 4. Start services
cd /opt/mirqab/cloud-relay
sudo docker compose up -d
```

### Option 2: Kubernetes (GKE/EKS/AKS)

```bash
# Apply base manifests
kubectl apply -k kubernetes/base

# Apply cloud-specific overlay (e.g., GCP)
kubectl apply -k kubernetes/overlays/gcp
```

### Option 3: Helm Chart

```bash
helm install cloud-relay ./helm/cloud-relay \
  --namespace mirqab \
  --create-namespace \
  -f helm/cloud-relay/values.yaml
```

## Services

| Service | Port | Description |
|---------|------|-------------|
| api-gateway | 8000 | Central routing |
| http-c2 | 8080 | HTTP C2 |
| c2-dns | 5353 | DNS C2 |
| exfil-server | 8081 | Exfiltration |
| payload-server | 8083 | Payloads |

## Health Check

```bash
curl http://localhost:8000/health
docker compose ps
```
EOF

echo "[6/6] Creating archive..."
cd "$OUTPUT_DIR"
tar -czf "$PACKAGE_NAME.tar.gz" "$PACKAGE_NAME"

echo ""
echo "============================================"
echo "  Package created successfully!"
echo "============================================"
echo "Location: $OUTPUT_DIR/$PACKAGE_NAME.tar.gz"
echo "Size: $(du -h "$OUTPUT_DIR/$PACKAGE_NAME.tar.gz" | cut -f1)"
echo ""
echo "To deploy:"
echo "  scp $OUTPUT_DIR/$PACKAGE_NAME.tar.gz user@target:/tmp/"
echo "  ssh user@target 'cd /tmp && tar -xzf $PACKAGE_NAME.tar.gz'"
echo ""
