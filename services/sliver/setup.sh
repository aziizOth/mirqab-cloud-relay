#!/bin/bash
# Sliver C2 Setup Script for Mirqab Cloud Relay
# Configures listeners and generates operator credentials

set -e

SLIVER_HOST="${SLIVER_HOST:-localhost}"
HTTPS_PORT="${HTTPS_PORT:-443}"
HTTP_PORT="${HTTP_PORT:-8888}"
DNS_DOMAIN="${DNS_DOMAIN:-c2.relay.local}"

echo "=== Mirqab Sliver C2 Setup ==="
echo "Host: $SLIVER_HOST"
echo "HTTPS Port: $HTTPS_PORT"
echo "HTTP Port: $HTTP_PORT"
echo "DNS Domain: $DNS_DOMAIN"

# Wait for Sliver server to be ready
echo "Waiting for Sliver server..."
sleep 10

# Start listeners using Sliver console commands
echo "Starting HTTPS listener on port $HTTPS_PORT..."
sliver-server https --lhost 0.0.0.0 --lport $HTTPS_PORT &

echo "Starting HTTP listener on port $HTTP_PORT..."
sliver-server http --lhost 0.0.0.0 --lport $HTTP_PORT &

echo "Starting DNS listener for $DNS_DOMAIN..."
sliver-server dns --domains $DNS_DOMAIN &

echo "=== Sliver C2 Setup Complete ==="
echo "Listeners active:"
echo "  - HTTPS: 0.0.0.0:$HTTPS_PORT"
echo "  - HTTP:  0.0.0.0:$HTTP_PORT"
echo "  - DNS:   $DNS_DOMAIN"
