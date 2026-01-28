#!/bin/bash
# Validate Cloud Relay Phase 2 security hardening
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
PASS=0
FAIL=0
WARN=0

check() {
    local label="$1" result="$2"
    if [ "$result" = "pass" ]; then
        echo "  [PASS] $label"
        PASS=$((PASS + 1))
    elif [ "$result" = "warn" ]; then
        echo "  [WARN] $label"
        WARN=$((WARN + 1))
    else
        echo "  [FAIL] $label"
        FAIL=$((FAIL + 1))
    fi
}

echo "=== Cloud Relay Security Hardening Validation ==="
echo ""

# 1. Secrets
echo "[Secrets]"
if grep -q 'POSTGRES_PASSWORD=relay' "$PROJECT_DIR/docker-compose.yml" 2>/dev/null; then
    check "No hardcoded DB password" "fail"
else
    check "No hardcoded DB password" "pass"
fi

if grep -q 'local-dev-key-change-me' "$PROJECT_DIR/docker-compose.yml" 2>/dev/null; then
    check "No weak default signing keys" "fail"
else
    check "No weak default signing keys" "pass"
fi

if [ -f "$PROJECT_DIR/.env" ]; then
    check ".env file exists" "pass"
else
    check ".env file exists (run generate-secrets.sh)" "warn"
fi

if [ -f "$PROJECT_DIR/.env.template" ]; then
    check ".env.template documented" "pass"
else
    check ".env.template documented" "fail"
fi

# 2. TLS
echo ""
echo "[TLS]"
if [ -f "$PROJECT_DIR/traefik/dynamic.yml" ]; then
    if grep -q 'VersionTLS13' "$PROJECT_DIR/traefik/dynamic.yml"; then
        check "TLS 1.3 enforced in Traefik" "pass"
    else
        check "TLS 1.3 enforced in Traefik" "fail"
    fi
else
    check "Traefik TLS config exists" "fail"
fi

if [ -d "$PROJECT_DIR/traefik/certs" ] && [ -f "$PROJECT_DIR/traefik/certs/server.crt" ]; then
    check "TLS certificates generated" "pass"
else
    check "TLS certificates (run generate-tls-certs.sh)" "warn"
fi

# 3. Kubernetes
echo ""
echo "[Kubernetes]"
for f in rbac-system resource-quota-system network-policy-strict api-gateway-deployment; do
    if [ -f "$PROJECT_DIR/kubernetes/base/${f}.yaml" ]; then
        check "$f.yaml exists" "pass"
    else
        check "$f.yaml exists" "fail"
    fi
done

# 4. Git safety
echo ""
echo "[Git Safety]"
if grep -q 'secrets/' "$PROJECT_DIR/.gitignore" 2>/dev/null; then
    check "secrets/ in .gitignore" "pass"
else
    check "secrets/ in .gitignore" "fail"
fi

if grep -q '\.env' "$PROJECT_DIR/.gitignore" 2>/dev/null; then
    check ".env in .gitignore" "pass"
else
    check ".env in .gitignore" "fail"
fi

echo ""
echo "=== Results: $PASS passed, $FAIL failed, $WARN warnings ==="
[ "$FAIL" -eq 0 ] && echo "Hardening validation PASSED." || echo "Hardening validation FAILED."
exit "$FAIL"
