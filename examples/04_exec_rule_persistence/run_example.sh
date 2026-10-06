#!/usr/bin/env bash
# ==============================================================================
# ulp-driver: ULP Example 4 - Persistent In-Kernel Execve Startup Rules
#
# This example demonstrates automatic startup livepatching for new processes:
# 1. Compiling a standalone worker binary (task_worker).
# 2. Running task_worker to verify initial unpatched behavior (status=1).
# 3. Registering an in-kernel persistent rule using ulp_ctl add-rule.
# 4. Running task_worker again — the kernel intercepts execve() before userspace
#    code starts and hotpatches the function (status=0), with zero manual injection!
# 5. Deleting the rule using ulp_ctl del-rule and verifying return to baseline.
# ==============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
ULP_DRIVER_DIR="$REPO_DIR/ulp-driver"
ULP_CTL="${ULP_CTL:-$ULP_DRIVER_DIR/ulp_ctl}"
[ -x "$ULP_CTL" ] || { echo "Missing $ULP_CTL. Build the tools first: make -C $ULP_DRIVER_DIR" >&2; exit 1; }

GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${BLUE}======================================================================${NC}"
echo -e "${BLUE}  EXAMPLE 4: Persistent In-Kernel Execve Startup Rules                ${NC}"
echo -e "${BLUE}======================================================================${NC}"

if [ "$(id -u)" -ne 0 ]; then
    echo -e "${RED}[ERROR] This example requires root privileges.${NC}"
    exit 1
fi

# Step 1: Ensure kernel driver is loaded
echo -e "\n${YELLOW}>>> [Step 1] Verifying ULP kernel driver status...${NC}"
if ! lsmod | grep -q "^ulp_driver"; then
    echo "[*] Inserting ulp_driver.ko (dev_mode=1)..."
    insmod "$ULP_DRIVER_DIR/ulp_driver.ko" dev_mode=1 allow_resumption=1 resume=1
fi
echo -e "${GREEN}[+] ULP kernel driver is active.${NC}"

# Step 2: Build task worker binary
echo -e "\n${YELLOW}>>> [Step 2] Compiling task_worker binary...${NC}"
make -C "$SCRIPT_DIR" clean
make -C "$SCRIPT_DIR"

BIN_PATH="$SCRIPT_DIR/task_worker"

# Step 3: Run baseline worker without rules
echo -e "\n${YELLOW}>>> [Step 3] Running task_worker without active rules...${NC}"
RESP=$("$BIN_PATH")
echo -e "Worker Output: ${BLUE}$RESP${NC}"
if [[ "$RESP" != *"LEGACY_UNPATCHED"* ]]; then
    echo -e "${RED}[FAIL] Expected LEGACY_UNPATCHED, got: $RESP${NC}"
    exit 1
fi
echo -e "${GREEN}[+] Baseline unpatched execution verified!${NC}"

# Step 4: Resolve symbol offset
echo -e "\n${YELLOW}>>> [Step 4] Resolving target function offset...${NC}"
TARGET_OFFSET="0x$(nm "$BIN_PATH" | grep -w "check_security_status" | awk '{print $1}')"
echo "[+] Target function offset: $TARGET_OFFSET in $BIN_PATH"

# Step 5: Register persistent in-kernel rule
echo -e "\n${YELLOW}>>> [Step 5] Registering persistent in-kernel rule via ulp_ctl...${NC}"
# patch_vaddr=0 instructs the driver to inject a safe 'xor %eax, %eax; ret' stub
"$ULP_CTL" add-rule "$BIN_PATH" "auto_sec_fix" "check_security_status" "$TARGET_OFFSET" 0 16 0 1

echo -e "\n[*] Active in-kernel rules:"
"$ULP_CTL" list-rules

# Step 6: Execute task_worker with rule active
echo -e "\n${YELLOW}>>> [Step 6] Executing task_worker with in-kernel rule active...${NC}"
echo "[*] Launching $BIN_PATH (Kernel will intercept execve)..."
RESP=$("$BIN_PATH")
echo -e "Worker Output: ${GREEN}$RESP${NC}"
if [[ "$RESP" != *"SECURED_BY_IN_KERNEL_RULE"* ]]; then
    echo -e "${RED}[FAIL] Execve livepatching rule did not trigger! Got: $RESP${NC}"
    exit 1
fi
echo -e "${GREEN}[+] SUCCESS: Newly exec'd binary was automatically livepatched at launch!${NC}"

# Step 7: Delete persistent rule
echo -e "\n${YELLOW}>>> [Step 7] Deleting persistent rule via ulp_ctl del-rule...${NC}"
"$ULP_CTL" del-rule "$BIN_PATH" "$TARGET_OFFSET"

echo -e "\n[*] Active in-kernel rules post-deletion:"
"$ULP_CTL" list-rules

# Step 8: Execute task_worker post-deletion
echo -e "\n${YELLOW}>>> [Step 8] Executing task_worker post-deletion...${NC}"
RESP=$("$BIN_PATH")
echo -e "Worker Output: ${BLUE}$RESP${NC}"
if [[ "$RESP" != *"LEGACY_UNPATCHED"* ]]; then
    echo -e "${RED}[FAIL] Baseline not restored after rule deletion! Got: $RESP${NC}"
    exit 1
fi
echo -e "${GREEN}[+] SUCCESS: Baseline behavior restored upon rule removal!${NC}"

echo -e "\n${GREEN}======================================================================${NC}"
echo -e "${GREEN}>>> EXAMPLE 4 COMPLETED SUCCESSFULLY: ALL CHECKS PASSED!            <<<${NC}"
echo -e "${GREEN}======================================================================${NC}"
