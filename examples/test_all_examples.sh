#!/usr/bin/env bash
# ==============================================================================
# ulp-driver: Master Test & Verification Suite for All ULP Examples
#
# Runs all 4 end-to-end examples in sequence, validating correctness across:
# 1. Basic C service livepatching (ulp_inject + ulp_ctl apply/revert).
# 2. Driver unload, state serialization (/run/ulp/state.bin), and resumption reload.
# 3. Rust application livepatching, ABI handling, and 16-byte CET trampolines.
# 4. In-kernel execve persistent startup rules (kprobe task_work interception).
# ==============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
RED='\033[0;31m'
BOLD='\033[1m'
NC='\033[0m'

echo -e "${BOLD}${BLUE}================================================================================${NC}"
echo -e "${BOLD}${BLUE}        ULP-DRIVER: MASTER EXAMPLES TEST HARNESS & RUNNER               ${NC}"
echo -e "${BOLD}${BLUE}================================================================================${NC}"

if [ "$(id -u)" -ne 0 ]; then
    echo -e "${RED}[ERROR] Root privileges required to execute ULP examples.${NC}"
    exit 1
fi

EXAMPLES=(
    "01_basic_c_service:Basic C Service Livepatching & Reversion"
    "02_driver_resumption_zero_downtime:Driver Unload, State Resumption & Zero Downtime"
    "03_rust_livepatch:Rust Application Livepatching & ABI Safety"
    "04_exec_rule_persistence:In-Kernel Persistent Execve Startup Rules"
)

TOTAL_START=$(date +%s)
RESULTS=()

for ENTRY in "${EXAMPLES[@]}"; do
    DIR="${ENTRY%%:*}"
    DESC="${ENTRY##*:}"
    
    echo -e "\n${BOLD}${CYAN}>>> RUNNING SUITE: ${DIR} (${DESC})...${NC}\n"
    START_TIME=$(date +%s)
    
    if "$SCRIPT_DIR/$DIR/run_example.sh"; then
        END_TIME=$(date +%s)
        DURATION=$((END_TIME - START_TIME))
        RESULTS+=("${GREEN}[PASS]${NC}  ${DIR} (${DURATION}s) - ${DESC}")
    else
        END_TIME=$(date +%s)
        DURATION=$((END_TIME - START_TIME))
        RESULTS+=("${RED}[FAIL]${NC}  ${DIR} (${DURATION}s) - ${DESC}")
        echo -e "\n${RED}[FATAL] Example suite $DIR failed! Aborting remaining tests.${NC}"
        exit 1
    fi
done

TOTAL_END=$(date +%s)
TOTAL_DURATION=$((TOTAL_END - TOTAL_START))

echo -e "\n${BOLD}${BLUE}================================================================================${NC}"
echo -e "${BOLD}${BLUE}                         FINAL EXECUTION SUMMARY                                ${NC}"
echo -e "${BOLD}${BLUE}================================================================================${NC}"
for R in "${RESULTS[@]}"; do
    echo -e "  $R"
done
echo -e "${BOLD}${BLUE}--------------------------------------------------------------------------------${NC}"
echo -e "  ${BOLD}Total Suites Executed:${NC} 4 / 4"
echo -e "  ${BOLD}Overall Status:${NC}        ${GREEN}100% PASSED${NC}"
echo -e "  ${BOLD}Total Time Elapsed:${NC}    ${TOTAL_DURATION} seconds"
echo -e "${BOLD}${BLUE}================================================================================${NC}"
