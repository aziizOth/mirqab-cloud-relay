#!/bin/bash
# Mirqab Cloud Relay - E2E Test Runner
#
# Usage: ./run_e2e_tests.sh [options]
#
# Options:
#   --waf-only      Run only WAF tests
#   --c2-only       Run only C2 tests
#   --verbose       Enable verbose output
#   --parallel      Run tests in parallel

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$(dirname "$SCRIPT_DIR")")"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Default options
RUN_WAF=true
RUN_C2=true
VERBOSE=""
PARALLEL=""

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --waf-only)
            RUN_C2=false
            shift
            ;;
        --c2-only)
            RUN_WAF=false
            shift
            ;;
        --verbose)
            VERBOSE="-v"
            shift
            ;;
        --parallel)
            PARALLEL="-n auto"
            shift
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}  Mirqab Cloud Relay - E2E Test Suite  ${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""

# Check prerequisites
echo -e "${YELLOW}Checking prerequisites...${NC}"

if ! command -v python3 &> /dev/null; then
    echo -e "${RED}Error: Python 3 is required${NC}"
    exit 1
fi

if ! python3 -c "import pytest" &> /dev/null; then
    echo -e "${RED}Error: pytest is required. Install with: pip install pytest pytest-asyncio httpx dnspython${NC}"
    exit 1
fi

# Configuration check
echo -e "${YELLOW}Checking configuration...${NC}"

# Check if Cloud Relay is reachable (optional)
CLOUD_RELAY_URL="${CLOUD_RELAY_URL:-https://api.relay.mirqab.io}"
echo "Cloud Relay URL: $CLOUD_RELAY_URL"

MASTER_URL="${MASTER_URL:-https://api.offensight.local:8000}"
echo "Master URL: $MASTER_URL"

echo ""

# Run tests
cd "$SCRIPT_DIR"

PYTEST_ARGS="$VERBOSE $PARALLEL --asyncio-mode=auto"

if $RUN_WAF; then
    echo -e "${YELLOW}Running WAF Integration Tests...${NC}"
    python3 -m pytest test_waf_integration.py $PYTEST_ARGS || WAF_FAILED=true
    echo ""
fi

if $RUN_C2; then
    echo -e "${YELLOW}Running C2 Callback Tests...${NC}"
    python3 -m pytest test_c2_callback.py $PYTEST_ARGS || C2_FAILED=true
    echo ""
fi

# Summary
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}              Test Summary              ${NC}"
echo -e "${GREEN}========================================${NC}"

if [[ -n "$WAF_FAILED" ]]; then
    echo -e "  WAF Tests:    ${RED}FAILED${NC}"
else
    echo -e "  WAF Tests:    ${GREEN}PASSED${NC}"
fi

if [[ -n "$C2_FAILED" ]]; then
    echo -e "  C2 Tests:     ${RED}FAILED${NC}"
else
    echo -e "  C2 Tests:     ${GREEN}PASSED${NC}"
fi

echo ""

if [[ -n "$WAF_FAILED" || -n "$C2_FAILED" ]]; then
    echo -e "${RED}Some tests failed. See above for details.${NC}"
    exit 1
else
    echo -e "${GREEN}All tests passed!${NC}"
fi
