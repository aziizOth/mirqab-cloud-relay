#!/bin/bash
# Generate self-signed TLS certificates for Cloud Relay local development
# Usage: ./scripts/generate-tls-certs.sh [domain]
#
# For production, use Let's Encrypt or your organization's CA.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
CERTS_DIR="$PROJECT_DIR/traefik/certs"
DOMAIN="${1:-relay.local}"

mkdir -p "$CERTS_DIR"

echo "Generating TLS certificates for domain: $DOMAIN"

# 1. Generate CA key and certificate
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-384 \
    -days 3650 -nodes \
    -keyout "$CERTS_DIR/ca.key" \
    -out "$CERTS_DIR/ca.pem" \
    -subj "/CN=Mirqab Cloud Relay CA/O=Mirqab/C=KW" \
    2>/dev/null

# 2. Generate server certificate
openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-384 \
    -nodes \
    -keyout "$CERTS_DIR/server.key" \
    -out "$CERTS_DIR/server.csr" \
    -subj "/CN=$DOMAIN/O=Mirqab/C=KW" \
    2>/dev/null

# Create SAN extension file
cat > "$CERTS_DIR/san.cnf" <<EOF
[req]
distinguished_name = req_dn
[req_dn]
[v3_ext]
subjectAltName = DNS:$DOMAIN,DNS:*.$DOMAIN,DNS:localhost,IP:127.0.0.1,IP:192.168.100.67
EOF

openssl x509 -req -in "$CERTS_DIR/server.csr" \
    -CA "$CERTS_DIR/ca.pem" \
    -CAkey "$CERTS_DIR/ca.key" \
    -CAcreateserial \
    -days 365 -sha384 \
    -extfile "$CERTS_DIR/san.cnf" \
    -extensions v3_ext \
    -out "$CERTS_DIR/server.crt" \
    2>/dev/null

# 3. Generate client CA for mTLS (separate from server CA)
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-384 \
    -days 3650 -nodes \
    -keyout "$CERTS_DIR/client-ca.key" \
    -out "$CERTS_DIR/client-ca.pem" \
    -subj "/CN=Mirqab Cloud Relay Client CA/O=Mirqab/C=KW" \
    2>/dev/null

# Clean up CSR and temp files
rm -f "$CERTS_DIR/server.csr" "$CERTS_DIR/san.cnf" "$CERTS_DIR/ca.srl"

# Set permissions
chmod 600 "$CERTS_DIR"/*.key
chmod 644 "$CERTS_DIR"/*.pem "$CERTS_DIR"/*.crt

echo "Certificates generated in $CERTS_DIR/"
echo "  CA:        ca.pem / ca.key"
echo "  Server:    server.crt / server.key (SAN: $DOMAIN, *.$DOMAIN, localhost)"
echo "  Client CA: client-ca.pem / client-ca.key (for mTLS)"
