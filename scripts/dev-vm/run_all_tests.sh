#!/usr/bin/env bash
# ulp-driver: copy the driver to one or more test VMs, build it there and run
# ulp-driver/test_ulp_modes.sh. Loads and unloads the module, so use
# disposable VMs only.
#
# Usage: run_all_tests.sh <ssh-host> [<ssh-host>...]
set -euo pipefail

if [ $# -eq 0 ]; then
    echo "usage: $0 <ssh-host> [<ssh-host>...]" >&2
    exit 2
fi

GREEN='\033[0;32m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m'

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
FAILED=()

sync_and_test() {
    local target="$1"
    echo -e "\n${BLUE}>>> $target ($(ssh "$target" uname -r))${NC}"

    echo "  1. Copying ulp-driver/ to $target:/root/ulp-driver/..."
    ssh "$target" 'mkdir -p /root/ulp-driver'
    scp -r "$REPO_DIR/ulp-driver" "$target:/root/ulp-driver/" >/dev/null

    echo "  2. Building and running test_ulp_modes.sh on $target..."
    ssh "$target" '
        set -e
        cd /root/ulp-driver/ulp-driver
        make clean && make
        ./test_ulp_modes.sh
    '
}

for host in "$@"; do
    if sync_and_test "$host"; then
        echo -e "  ${GREEN}$host: passed${NC}"
    else
        echo -e "  ${RED}$host: FAILED${NC}"
        FAILED+=("$host")
    fi
done

if [ ${#FAILED[@]} -ne 0 ]; then
    echo -e "\n${RED}Failed on: ${FAILED[*]}${NC}"
    exit 1
fi
echo -e "\n${GREEN}All hosts passed.${NC}"
