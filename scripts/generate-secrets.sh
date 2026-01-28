#!/bin/bash
# Generate cryptographically secure secrets for Cloud Relay
# Usage: ./scripts/generate-secrets.sh
#
# Creates a .env file with random secrets. If .env already exists,
# it will NOT be overwritten (use --force to overwrite).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
ENV_FILE="$PROJECT_DIR/.env"

if [ -f "$ENV_FILE" ] && [ "${1:-}" != "--force" ]; then
    echo "ERROR: .env already exists. Use --force to overwrite."
    exit 1
fi

echo "Generating secrets for Cloud Relay..."

POSTGRES_PASSWORD=$(openssl rand -hex 24)
REDIS_PASSWORD=$(openssl rand -hex 24)
SIGNING_KEY=$(openssl rand -hex 48)
C2_SIGNING_KEY=$(openssl rand -hex 48)
PHISHING_SIGNING_KEY=$(openssl rand -hex 48)
TEST_API_KEY="cr-test-$(openssl rand -hex 16)"
TEST_API_SECRET="cr-secret-$(openssl rand -hex 24)"

cat > "$ENV_FILE" <<EOF
# Mirqab Cloud Relay - Generated Secrets
# Generated: $(date -u +"%Y-%m-%dT%H:%M:%SZ")
# WARNING: Do not commit this file to git.

# Database
POSTGRES_USER=relay
POSTGRES_PASSWORD=$POSTGRES_PASSWORD
POSTGRES_DB=relay

# Redis
REDIS_PASSWORD=$REDIS_PASSWORD

# Signing Keys (HMAC-SHA256)
SIGNING_KEY=$SIGNING_KEY
C2_SIGNING_KEY=$C2_SIGNING_KEY
PHISHING_SIGNING_KEY=$PHISHING_SIGNING_KEY

# API Gateway
REQUIRE_MTLS=false
REQUIRE_SIGNATURE=false
DEBUG=true
ALLOWED_ORIGINS=http://localhost:3000,http://localhost:8000

# Test Credentials (only used when DEBUG=true)
TEST_API_KEY=$TEST_API_KEY
TEST_API_SECRET=$TEST_API_SECRET

# Cloud Relay Host
CLOUD_RELAY_HOST=192.168.100.67
CLOUD_RELAY_DOMAIN=relay.local
EOF

chmod 600 "$ENV_FILE"
echo "Secrets written to $ENV_FILE"
echo "  POSTGRES_PASSWORD: ${POSTGRES_PASSWORD:0:8}..."
echo "  REDIS_PASSWORD:    ${REDIS_PASSWORD:0:8}..."
echo "  SIGNING_KEY:       ${SIGNING_KEY:0:8}..."
echo "  TEST_API_KEY:      $TEST_API_KEY"
