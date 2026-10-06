#!/usr/bin/env bash
# ==============================================================================
# ulp-driver: ULP Example 2 - Kernel Driver Resumption & Zero Downtime
#
# This example demonstrates ULP's unique driver upgrade and resumption lifecycle:
# 1. Loading the ulp_driver kernel module with allow_resumption=1 and resume=1.
# 2. Livepatching an active, concurrent worker daemon.
# 3. UNLOADING the kernel driver (rmmod ulp_driver) — the driver serializes its
#    active patch state into /run/ulp/state.bin without touching userspace memory.
# 4. Proving 100% ZERO-DOWNTIME continuity: the userspace daemon continues to
#    execute patched code and serve queries while ulp_driver is NOT loaded!
# 5. RELOADING the kernel driver (insmod ulp_driver.ko resume=1) — the driver
#    deserializes state, re-verifies memory trampolines, and adopts all patches.
# 6. Reverting the patch cleanly with the newly loaded driver instance.
# ==============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
ULP_DRIVER_DIR="$REPO_DIR/ulp-driver"
ULP_CTL="${ULP_CTL:-/usr/local/bin/ulp_ctl}"
ULP_INJECT="${ULP_INJECT:-/usr/local/bin/ulp_inject}"

GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${BLUE}======================================================================${NC}"
echo -e "${BLUE}  EXAMPLE 2: Driver Resumption & Zero-Downtime Reloading              ${NC}"
echo -e "${BLUE}======================================================================${NC}"

if [ "$(id -u)" -ne 0 ]; then
    echo -e "${RED}[ERROR] This example requires root privileges to reload kernel modules.${NC}"
    exit 1
fi

# Step 1: Ensure clean driver load with resumption enabled
echo -e "\n${YELLOW}>>> [Step 1] Loading ulp_driver with allow_resumption=1 and resume=1...${NC}"
rmmod livepatch_ulp 2>/dev/null || true
rmmod ulp_driver 2>/dev/null || true
rm -f /run/ulp/state.bin /run/ulp_state.bin

insmod "$ULP_DRIVER_DIR/ulp_driver.ko" dev_mode=1 allow_resumption=1 resume=1
echo -e "${GREEN}[+] Driver loaded. Resumption parameters:${NC}"
echo "    allow_resumption = $(cat /sys/module/ulp_driver/parameters/allow_resumption)"
echo "    resume           = $(cat /sys/module/ulp_driver/parameters/resume)"

# Step 2: Build target worker and patch
echo -e "\n${YELLOW}>>> [Step 2] Building worker service and patch payload...${NC}"
make -C "$SCRIPT_DIR" clean
make -C "$SCRIPT_DIR"

# Step 3: Start worker service
echo -e "\n${YELLOW}>>> [Step 3] Launching worker daemon...${NC}"
"$SCRIPT_DIR/worker_service" &
WORKER_PID=$!
sleep 0.5

cleanup() {
    echo -e "\n[*] Cleaning up..."
    if kill -0 "$WORKER_PID" 2>/dev/null; then
        kill "$WORKER_PID" 2>/dev/null || true
        wait "$WORKER_PID" 2>/dev/null || true
    fi
    rm -f /tmp/ulp_example_resumption.sock
    echo "[+] Cleaned up worker daemon."
}
trap cleanup EXIT

echo -e "${GREEN}[+] Worker running on PID: $WORKER_PID${NC}"

# Step 4: Inject and apply livepatch
echo -e "\n${YELLOW}>>> [Step 4] Injecting and applying livepatch...${NC}"
"$ULP_INJECT" "$WORKER_PID" "$SCRIPT_DIR/worker_patch.so"
sleep 0.2

TARGET_VADDR="0x$(nm "$SCRIPT_DIR/worker_service" | grep -w "process_work_unit" | awk '{print $1}')"
SO_BASE_HEX=$(grep "worker_patch.so" "/proc/$WORKER_PID/maps" | head -n 1 | awk '{print $1}' | cut -d- -f1)
SO_OFF_HEX=$(nm -D "$SCRIPT_DIR/worker_patch.so" | grep -w "livepatch_process_work_unit" | awk '{print $1}')
PATCH_VADDR=$(python3 -c "print(hex(0x$SO_BASE_HEX + 0x$SO_OFF_HEX))")

"$ULP_CTL" apply "$WORKER_PID" "resumption_patch" "process_work_unit" "$TARGET_VADDR" "$PATCH_VADDR" 16

echo -e "\n[*] Active livepatches before driver unload:"
cat /proc/ulp_patches

# Verify livepatch is active
RESP=$("$SCRIPT_DIR/worker_service" --query 1)
echo -e "Initial Query Response: ${GREEN}$RESP${NC}"
if [[ "$RESP" != *"v2_ACCELERATED"* ]]; then
    echo -e "${RED}[FAIL] Livepatch was not applied correctly!${NC}"
    exit 1
fi

# Step 5: Unload the kernel driver
echo -e "\n${CYAN}======================================================================${NC}"
echo -e "${CYAN}>>> [Step 5] UNLOADING ULP KERNEL DRIVER (Simulating Driver Upgrade)   ${NC}"
echo -e "${CYAN}======================================================================${NC}"
echo "[*] Executing: rmmod ulp_driver"
rmmod ulp_driver

# Verify driver is NOT loaded in kernel
if lsmod | grep -q "^ulp_driver"; then
    echo -e "${RED}[FAIL] ulp_driver is still loaded!${NC}"
    exit 1
fi
echo -e "${GREEN}[+] Driver unloaded cleanly. Module is absent from the Linux kernel!${NC}"

# Verify state serialization file exists
STATE_FILE="/run/ulp/state.bin"
if [ ! -f "$STATE_FILE" ]; then
    STATE_FILE="/run/ulp_state.bin"
fi
if [ ! -f "$STATE_FILE" ]; then
    echo -e "${RED}[FAIL] State snapshot file not found!${NC}"
    exit 1
fi
echo -e "${GREEN}[+] Driver state persisted to: $STATE_FILE ($(stat -c%s "$STATE_FILE") bytes)${NC}"

# Step 6: Query service WHILE KERNEL DRIVER IS UNLOADED
echo -e "\n${YELLOW}>>> [Step 6] Testing queries WHILE KERNEL DRIVER IS UNLOADED...${NC}"
echo "[*] Issuing 5 concurrent transactions against PID $WORKER_PID..."
for i in $(seq 1 5); do
    RESP=$("$SCRIPT_DIR/worker_service" --query 1)
    echo -n "    Query #$i: $RESP"
    if [[ "$RESP" != *"v2_ACCELERATED"* ]]; then
        echo -e "${RED}[FAIL] Service lost livepatched code while driver was unloaded!${NC}"
        exit 1
    fi
done
echo -e "${GREEN}[+] ZERO-DOWNTIME PROVEN: Userspace executed hotpatched code with ZERO kernel driver loaded!${NC}"

# Step 7: Reload driver and resume state
echo -e "\n${CYAN}======================================================================${NC}"
echo -e "${CYAN}>>> [Step 7] RELOADING KERNEL DRIVER (resume=1 allow_resumption=1)     ${NC}"
echo -e "${CYAN}======================================================================${NC}"
echo "[*] Executing: insmod ulp_driver.ko dev_mode=1 resume=1 allow_resumption=1"
insmod "$ULP_DRIVER_DIR/ulp_driver.ko" dev_mode=1 resume=1 allow_resumption=1
echo -e "${GREEN}[+] Driver reloaded successfully.${NC}"

# Step 8: Verify automatic re-adoption
echo -e "\n${YELLOW}>>> [Step 8] Verifying patch re-adoption in new driver instance...${NC}"
echo -e "[*] Active livepatches in reloaded driver (/proc/ulp_patches):"
cat /proc/ulp_patches
if ! grep -q "resumption_patch" /proc/ulp_patches; then
    echo -e "${RED}[FAIL] Driver failed to re-adopt resumption_patch from state file!${NC}"
    exit 1
fi
echo -e "${GREEN}[+] SUCCESS: Reloaded driver automatically re-adopted active livepatch!${NC}"

# Step 9: Revert livepatch using the NEW driver instance
echo -e "\n${YELLOW}>>> [Step 9] Reverting livepatch using new driver instance...${NC}"
"$ULP_CTL" revert "$WORKER_PID" "$TARGET_VADDR"

echo -e "\n[*] Active livepatches post-revert (/proc/ulp_patches):"
cat /proc/ulp_patches

# Step 10: Verify baseline restoration
echo -e "\n${YELLOW}>>> [Step 10] Querying worker to verify baseline restoration...${NC}"
RESP=$("$SCRIPT_DIR/worker_service" --query 1)
echo -e "Post-revert Response: ${BLUE}$RESP${NC}"
if [[ "$RESP" != *"v1_standard"* ]]; then
    echo -e "${RED}[FAIL] Baseline not restored! Got: $RESP${NC}"
    exit 1
fi
echo -e "${GREEN}[+] Baseline unpatched execution restored!${NC}"

echo -e "\n${GREEN}======================================================================${NC}"
echo -e "${GREEN}>>> EXAMPLE 2 COMPLETED SUCCESSFULLY: ALL CHECKS PASSED!            <<<${NC}"
echo -e "${GREEN}======================================================================${NC}"
