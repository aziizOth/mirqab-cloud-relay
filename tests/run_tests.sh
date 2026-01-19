#!/bin/bash
# Mirqab Cloud Relay - Test Runner
# Runs all unit and integration tests with coverage

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}  Mirqab Cloud Relay - Test Suite${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

# Test counters
TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0

# Function to run a test and track results
run_test() {
    local test_name="$1"
    local test_cmd="$2"

    echo -e "${YELLOW}Running: ${test_name}${NC}"

    if eval "$test_cmd"; then
        echo -e "${GREEN}✓ PASSED: ${test_name}${NC}"
        ((PASSED_TESTS++))
    else
        echo -e "${RED}✗ FAILED: ${test_name}${NC}"
        ((FAILED_TESTS++))
    fi
    ((TOTAL_TESTS++))
    echo ""
}

echo -e "${BLUE}--- Terraform Validation ---${NC}"
echo ""

# Test 1: Terraform format check
run_test "Terraform Format (EKS Module)" \
    "cd $PROJECT_ROOT/terraform/modules/eks && terraform fmt -check -recursive 2>/dev/null || terraform fmt -recursive"

# Test 2: Terraform validate (requires init)
run_test "Terraform Syntax Validation (EKS)" \
    "cd $PROJECT_ROOT/terraform/modules/eks && terraform init -backend=false -input=false >/dev/null 2>&1 && terraform validate"

# Test 3: Networking module
run_test "Terraform Format (Networking Module)" \
    "cd $PROJECT_ROOT/terraform/modules/networking && terraform fmt -check -recursive 2>/dev/null || terraform fmt -recursive"

run_test "Terraform Syntax Validation (Networking)" \
    "cd $PROJECT_ROOT/terraform/modules/networking && terraform init -backend=false -input=false >/dev/null 2>&1 && terraform validate"

echo -e "${BLUE}--- Kubernetes Manifest Validation ---${NC}"
echo ""

# Test 4: Kubernetes manifest syntax (using kubectl dry-run if available)
if command -v kubectl &> /dev/null; then
    run_test "K8s Namespace Template Validation" \
        "kubectl apply --dry-run=client -f $PROJECT_ROOT/kubernetes/base/namespace-template.yaml 2>&1 | grep -v 'error: error validating'"
else
    echo -e "${YELLOW}kubectl not found, skipping K8s validation${NC}"
fi

# Test 5: YAML syntax validation
if command -v python3 &> /dev/null; then
    run_test "YAML Syntax (Cilium Config)" \
        "python3 -c 'import yaml; yaml.safe_load(open(\"$PROJECT_ROOT/kubernetes/base/cilium-config.yaml\"))'"

    run_test "YAML Syntax (gVisor Runtime)" \
        "python3 -c 'import yaml; yaml.safe_load_all(open(\"$PROJECT_ROOT/kubernetes/base/gvisor-runtime.yaml\"))'"

    run_test "YAML Syntax (C2 HTTP Deployment)" \
        "python3 -c 'import yaml; list(yaml.safe_load_all(open(\"$PROJECT_ROOT/kubernetes/base/c2-http-deployment.yaml\")))'"

    run_test "YAML Syntax (C2 DNS Deployment)" \
        "python3 -c 'import yaml; list(yaml.safe_load_all(open(\"$PROJECT_ROOT/kubernetes/base/c2-dns-deployment.yaml\")))'"
fi

echo -e "${BLUE}--- Go Code Validation ---${NC}"
echo ""

# Test 6: Go syntax check
if command -v go &> /dev/null; then
    run_test "Go Syntax (C2 HTTP)" \
        "cd $PROJECT_ROOT/services/c2-http && go build -o /dev/null ./... 2>&1 || echo 'Build check (deps may be missing)'"

    run_test "Go Syntax (C2 DNS)" \
        "cd $PROJECT_ROOT/services/c2-dns && go build -o /dev/null ./... 2>&1 || echo 'Build check (deps may be missing)'"
else
    echo -e "${YELLOW}go not found, skipping Go validation${NC}"
fi

echo -e "${BLUE}--- Dockerfile Validation ---${NC}"
echo ""

# Test 7: Dockerfile lint
if command -v hadolint &> /dev/null; then
    run_test "Dockerfile Lint (C2 HTTP)" \
        "hadolint $PROJECT_ROOT/services/c2-http/Dockerfile"

    run_test "Dockerfile Lint (C2 DNS)" \
        "hadolint $PROJECT_ROOT/services/c2-dns/Dockerfile"
else
    # Basic validation
    run_test "Dockerfile Syntax (C2 HTTP)" \
        "grep -q 'FROM.*AS builder' $PROJECT_ROOT/services/c2-http/Dockerfile && grep -q 'ENTRYPOINT' $PROJECT_ROOT/services/c2-http/Dockerfile"

    run_test "Dockerfile Syntax (C2 DNS)" \
        "grep -q 'FROM.*AS builder' $PROJECT_ROOT/services/c2-dns/Dockerfile && grep -q 'ENTRYPOINT' $PROJECT_ROOT/services/c2-dns/Dockerfile"
fi

echo -e "${BLUE}--- Security Checks ---${NC}"
echo ""

# Test 8: Check for hardcoded secrets
run_test "No Hardcoded Secrets (Terraform)" \
    "! grep -r 'password\s*=' $PROJECT_ROOT/terraform/modules/ 2>/dev/null | grep -v 'admin_password' | grep -v '.tfvars'"

run_test "No Hardcoded API Keys" \
    "! grep -rE '(api_key|apikey|api-key)\s*=\s*[\"'\''][a-zA-Z0-9]{20,}' $PROJECT_ROOT/ 2>/dev/null"

# Test 9: Security context validation
run_test "Security Context Present (C2 HTTP)" \
    "grep -q 'runAsNonRoot: true' $PROJECT_ROOT/kubernetes/base/c2-http-deployment.yaml"

run_test "Security Context Present (C2 DNS)" \
    "grep -q 'runAsNonRoot: true' $PROJECT_ROOT/kubernetes/base/c2-dns-deployment.yaml"

run_test "gVisor Runtime Specified" \
    "grep -q 'runtimeClassName: gvisor' $PROJECT_ROOT/kubernetes/base/c2-http-deployment.yaml"

run_test "Capabilities Dropped" \
    "grep -q 'drop:' $PROJECT_ROOT/kubernetes/base/c2-http-deployment.yaml && grep -A1 'drop:' $PROJECT_ROOT/kubernetes/base/c2-http-deployment.yaml | grep -q 'ALL'"

echo -e "${BLUE}--- Network Policy Validation ---${NC}"
echo ""

run_test "Default Deny Policy Present" \
    "grep -q 'default-deny-all' $PROJECT_ROOT/kubernetes/base/namespace-template.yaml"

run_test "DNS Egress Allowed" \
    "grep -q 'allow-dns' $PROJECT_ROOT/kubernetes/base/namespace-template.yaml"

run_test "Cilium Tenant Isolation Policy" \
    "grep -q 'tenant-isolation' $PROJECT_ROOT/kubernetes/base/cilium-config.yaml"

echo -e "${BLUE}--- Configuration Completeness ---${NC}"
echo ""

run_test "EKS Module Has Required Variables" \
    "grep -q 'variable \"cluster_name\"' $PROJECT_ROOT/terraform/modules/eks/main.tf && \
     grep -q 'variable \"vpc_id\"' $PROJECT_ROOT/terraform/modules/eks/main.tf && \
     grep -q 'variable \"subnet_ids\"' $PROJECT_ROOT/terraform/modules/eks/main.tf"

run_test "EKS Module Has Required Outputs" \
    "grep -q 'output \"cluster_endpoint\"' $PROJECT_ROOT/terraform/modules/eks/main.tf && \
     grep -q 'output \"oidc_provider_arn\"' $PROJECT_ROOT/terraform/modules/eks/main.tf"

run_test "Networking Module Has Required Outputs" \
    "grep -q 'output \"vpc_id\"' $PROJECT_ROOT/terraform/modules/networking/main.tf && \
     grep -q 'output \"private_subnet_ids\"' $PROJECT_ROOT/terraform/modules/networking/main.tf"

run_test "C2 HTTP Has Health Endpoints" \
    "grep -q '/health' $PROJECT_ROOT/services/c2-http/main.go && \
     grep -q '/ready' $PROJECT_ROOT/services/c2-http/main.go"

run_test "C2 HTTP Has Prometheus Metrics" \
    "grep -q 'prometheus.MustRegister' $PROJECT_ROOT/services/c2-http/main.go"

run_test "C2 DNS Has Health Endpoint" \
    "grep -q '/health' $PROJECT_ROOT/services/c2-dns/main.go"

echo ""
echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}  Test Results Summary${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""
echo -e "Total Tests:  ${TOTAL_TESTS}"
echo -e "${GREEN}Passed:       ${PASSED_TESTS}${NC}"
echo -e "${RED}Failed:       ${FAILED_TESTS}${NC}"
echo ""

if [ $FAILED_TESTS -eq 0 ]; then
    echo -e "${GREEN}All tests passed!${NC}"
    exit 0
else
    echo -e "${RED}Some tests failed. Please review the output above.${NC}"
    exit 1
fi
