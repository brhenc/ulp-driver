#!/usr/bin/env bash
# ==============================================================================
# ulp-driver: Unified End-to-End Regression Test Runner
# Tests Debian 13 and Fedora Rawhide VMs with comprehensive assertions
# ==============================================================================
set -euo pipefail

GREEN='\033[0;32m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${BLUE}======================================================================${NC}"
echo -e "${BLUE}        ULP-DRIVER: UNIFIED REGRESSION TEST BATTERY          ${NC}"
echo -e "${BLUE}======================================================================${NC}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

sync_and_test() {
    local target="$1"
    local desc="$2"
    echo -e "\n${BLUE}>>> [TEST TARGET: $target] ($desc) <<<${NC}"

    echo "  1. Synchronizing files to $target..."
    scp -r "$SCRIPT_DIR/ulp-driver" "$SCRIPT_DIR/frr-userspace-livepatch" "$SCRIPT_DIR/haproxy-livepatch" "$target:/root/ulp-driver/" >/dev/null

    echo "  2. Running automated test suite on $target..."
    ssh "$target" '
        set -e
        cd /root/ulp-driver/ulp-driver
        make clean && make
        install -m 755 ulp_ctl /usr/local/bin/ulp_ctl
        install -m 755 ulp_inject /usr/local/bin/ulp_inject
        chmod +x test_ulp_modes.sh
        ./test_ulp_modes.sh
    '
    echo -e "  ${GREEN}>>> $target PASSED ALL 25 TEST BATTERY ASSERTIONS <<<${NC}"
}

sync_and_test "debian-13" "Debian 13 Trixie / Linux 6.12.107+deb13"
sync_and_test "fkernel-dev" "Fedora Rawhide / Linux 7.3.0 (SELinux Enforcing)"

echo -e "\n${GREEN}======================================================================${NC}"
echo -e "${GREEN}  ALL TARGETS PASSED 100% REGRESSION SUITES (ZERO DEFECTS FOUND)      ${NC}"
echo -e "${GREEN}======================================================================${NC}"
