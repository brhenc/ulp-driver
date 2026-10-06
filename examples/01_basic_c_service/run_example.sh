#!/usr/bin/env bash
# ==============================================================================
# ulp-driver: ULP Example 1 - Basic C Userspace Livepatching
#
# This example demonstrates the fundamental end-to-end ULP workflow:
# 1. Building a standalone target C daemon and a livepatch payload shared library.
# 2. Starting the daemon and verifying baseline behavior.
# 3. Injecting the livepatch shared library via ulp_inject (ptrace dlopen).
# 4. Applying the livepatch into the active process using ulp_ctl.
# 5. Verifying live runtime interception with zero downtime or drops.
# 6. Reverting the livepatch and verifying restoration of baseline code.
# ==============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
ULP_DRIVER_DIR="$REPO_DIR/ulp-driver"
ULP_CTL="${ULP_CTL:-$ULP_DRIVER_DIR/ulp_ctl}"
ULP_INJECT="${ULP_INJECT:-$ULP_DRIVER_DIR/ulp_inject}"
for tool in "$ULP_CTL" "$ULP_INJECT"; do
    [ -x "$tool" ] || { echo "Missing $tool. Build the tools first: make -C $ULP_DRIVER_DIR" >&2; exit 1; }
done

GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${BLUE}======================================================================${NC}"
echo -e "${BLUE}  EXAMPLE 1: Basic Userspace Livepatching for C Services              ${NC}"
echo -e "${BLUE}======================================================================${NC}"

# Check for root privileges (required for /dev/ulp access)
if [ "$(id -u)" -ne 0 ]; then
    echo -e "${RED}[ERROR] This example requires root privileges to interact with /dev/ulp.${NC}"
    exit 1
fi

# Step 1: Ensure kernel driver is loaded
echo -e "\n${YELLOW}>>> [Step 1] Verifying ULP kernel driver status...${NC}"
if ! lsmod | grep -q "^ulp_driver"; then
    echo "[*] ulp_driver module not loaded. Inserting ulp_driver.ko (dev_mode=1)..."
    insmod "$ULP_DRIVER_DIR/ulp_driver.ko" dev_mode=1 allow_resumption=1 resume=1
fi
echo -e "${GREEN}[+] ULP kernel driver is active.${NC}"

# Step 2: Build target service and livepatch payload
echo -e "\n${YELLOW}>>> [Step 2] Compiling target service and patch payload...${NC}"
make -C "$SCRIPT_DIR" clean
make -C "$SCRIPT_DIR"

# Step 3: Start target service in the background
echo -e "\n${YELLOW}>>> [Step 3] Launching target_service daemon...${NC}"
"$SCRIPT_DIR/target_service" &
SERVICE_PID=$!
sleep 0.5

# Register trap to clean up on exit
cleanup() {
    echo -e "\n[*] Cleaning up..."
    if kill -0 "$SERVICE_PID" 2>/dev/null; then
        kill "$SERVICE_PID" 2>/dev/null || true
        wait "$SERVICE_PID" 2>/dev/null || true
    fi
    rm -f /tmp/ulp_example_c.sock
    echo "[+] Cleaned up target service."
}
trap cleanup EXIT

echo -e "${GREEN}[+] Target service running on PID: $SERVICE_PID${NC}"

# Step 4: Query baseline status
echo -e "\n${YELLOW}>>> [Step 4] Querying baseline (unpatched) service response...${NC}"
BASELINE_RESP=$("$SCRIPT_DIR/target_service" --query)
echo -e "Service Response: ${BLUE}$BASELINE_RESP${NC}"
if [[ "$BASELINE_RESP" != *"UNPATCHED"* ]]; then
    echo -e "${RED}[FAIL] Expected UNPATCHED response, got: $BASELINE_RESP${NC}"
    exit 1
fi
echo -e "${GREEN}[+] Baseline response verified!${NC}"

# Step 5: Inject patch_payload.so into target process
echo -e "\n${YELLOW}>>> [Step 5] Injecting patch_payload.so into PID $SERVICE_PID via ulp_inject...${NC}"
"$ULP_INJECT" "$SERVICE_PID" "$SCRIPT_DIR/patch_payload.so"
sleep 0.2

# Verify injection in /proc/$PID/maps
if ! grep -q "patch_payload.so" "/proc/$SERVICE_PID/maps"; then
    echo -e "${RED}[FAIL] patch_payload.so was not found in /proc/$SERVICE_PID/maps!${NC}"
    exit 1
fi
echo -e "${GREEN}[+] patch_payload.so mapped successfully into target memory.${NC}"

# Step 6: Calculate target and patch virtual addresses
echo -e "\n${YELLOW}>>> [Step 6] Resolving function virtual addresses...${NC}"
# Since target_service was compiled with -no-pie, nm reports the exact vaddr
TARGET_VADDR="0x$(nm "$SCRIPT_DIR/target_service" | grep -w "get_service_status" | awk '{print $1}')"

# For the shared object, add base VMA address to exported function offset
SO_BASE_HEX=$(grep "patch_payload.so" "/proc/$SERVICE_PID/maps" | head -n 1 | awk '{print $1}' | cut -d- -f1)
SO_OFF_HEX=$(nm -D "$SCRIPT_DIR/patch_payload.so" | grep -w "livepatch_get_service_status" | awk '{print $1}')
PATCH_VADDR=$(python3 -c "print(hex(0x$SO_BASE_HEX + 0x$SO_OFF_HEX))")

echo "[+] Target function : get_service_status          -> $TARGET_VADDR"
echo "[+] Patch function  : livepatch_get_service_status -> $PATCH_VADDR"

# Step 7: Apply livepatch using ulp_ctl
echo -e "\n${YELLOW}>>> [Step 7] Applying livepatch via ulp_ctl...${NC}"
"$ULP_CTL" apply "$SERVICE_PID" "example_c_patch" "get_service_status" "$TARGET_VADDR" "$PATCH_VADDR" 16

# Verify kernel patch registry
echo -e "\n[*] Active kernel livepatches (/proc/ulp_patches):"
cat /proc/ulp_patches

# Step 8: Query service to observe livepatched response
echo -e "\n${YELLOW}>>> [Step 8] Querying livepatched service response...${NC}"
PATCHED_RESP=$("$SCRIPT_DIR/target_service" --query)
echo -e "Service Response: ${GREEN}$PATCHED_RESP${NC}"
if [[ "$PATCHED_RESP" != *"LIVEPATCHED"* ]]; then
    echo -e "${RED}[FAIL] Livepatch failed! Service still returned: $PATCHED_RESP${NC}"
    exit 1
fi
echo -e "${GREEN}[+] LIVEPATCH VERIFIED: In-memory function execution hijacked successfully!${NC}"

# Step 9: Revert livepatch using ulp_ctl
echo -e "\n${YELLOW}>>> [Step 9] Reverting livepatch via ulp_ctl...${NC}"
"$ULP_CTL" revert "$SERVICE_PID" "$TARGET_VADDR"

echo -e "\n[*] Active kernel livepatches post-revert (/proc/ulp_patches):"
cat /proc/ulp_patches

# Step 10: Query service to verify baseline restoration
echo -e "\n${YELLOW}>>> [Step 10] Querying service after revert...${NC}"
REVERTED_RESP=$("$SCRIPT_DIR/target_service" --query)
echo -e "Service Response: ${BLUE}$REVERTED_RESP${NC}"
if [[ "$REVERTED_RESP" != *"UNPATCHED"* ]]; then
    echo -e "${RED}[FAIL] Revert failed! Service returned: $REVERTED_RESP${NC}"
    exit 1
fi
echo -e "${GREEN}[+] REVERT VERIFIED: Original code restored cleanly with zero downtime!${NC}"

echo -e "\n${GREEN}======================================================================${NC}"
echo -e "${GREEN}>>> EXAMPLE 1 COMPLETED SUCCESSFULLY: ALL CHECKS PASSED!            <<<${NC}"
echo -e "${GREEN}======================================================================${NC}"
