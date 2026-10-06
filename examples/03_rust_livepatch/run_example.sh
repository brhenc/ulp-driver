#!/usr/bin/env bash
# ==============================================================================
# ulp-driver: ULP Example 3 - Livepatching Rust Applications
#
# This example demonstrates livepatching modern Rust binaries:
# 1. Compiling a Rust binary and a dynamic library payload (cdylib).
# 2. ABI considerations: #[no_mangle], #[inline(never)], extern "C".
# 3. Dynamic PIE address resolution for compiled Rust symbols.
# 4. Injecting the cdylib and applying a 16-byte CET absolute trampoline.
# 5. Live verification and zero-downtime rollback.
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
echo -e "${BLUE}  EXAMPLE 3: Livepatching Rust Applications                           ${NC}"
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

# Step 2: Build Rust target and patch
echo -e "\n${YELLOW}>>> [Step 2] Compiling Rust daemon and cdylib patch payload...${NC}"
make -C "$SCRIPT_DIR" clean
make -C "$SCRIPT_DIR"

# Step 3: Start Rust daemon
echo -e "\n${YELLOW}>>> [Step 3] Launching rust_daemon...${NC}"
"$SCRIPT_DIR/rust_daemon" &
RUST_PID=$!
sleep 0.5

cleanup() {
    echo -e "\n[*] Cleaning up..."
    if kill -0 "$RUST_PID" 2>/dev/null; then
        kill "$RUST_PID" 2>/dev/null || true
        wait "$RUST_PID" 2>/dev/null || true
    fi
    rm -f /tmp/ulp_example_rust.sock
    echo "[+] Cleaned up Rust daemon."
}
trap cleanup EXIT

echo -e "${GREEN}[+] Rust daemon running on PID: $RUST_PID${NC}"

# Step 4: Query baseline
echo -e "\n${YELLOW}>>> [Step 4] Querying baseline Rust daemon response...${NC}"
RESP=$("$SCRIPT_DIR/rust_daemon" --query)
echo -e "Service Response: ${BLUE}$RESP${NC}"
if [[ "$RESP" != *"UNPATCHED"* ]]; then
    echo -e "${RED}[FAIL] Expected UNPATCHED, got: $RESP${NC}"
    exit 1
fi
echo -e "${GREEN}[+] Baseline Rust response verified!${NC}"

# Step 5: Inject cdylib into Rust process
echo -e "\n${YELLOW}>>> [Step 5] Injecting libpatch_rust.so into PID $RUST_PID via ulp_inject...${NC}"
"$ULP_INJECT" "$RUST_PID" "$SCRIPT_DIR/libpatch_rust.so"
sleep 0.2

# Step 6: Resolve virtual addresses
echo -e "\n${YELLOW}>>> [Step 6] Resolving Rust symbol virtual addresses...${NC}"
ADDRS=$(python3 -c "
import subprocess

def get_vma_base(pid, substr):
    with open(f'/proc/{pid}/maps') as f:
        for line in f:
            if substr in line and '00000000' in line:
                return int(line.split()[0].split('-')[0], 16)
    return None

def get_symbol_off(exe, sym):
    out = subprocess.check_output(f'nm {exe} 2>/dev/null | grep -w \"{sym}\"', shell=True, text=True).strip()
    return int(out.split()[0], 16)

pid = $RUST_PID
exe = '$SCRIPT_DIR/rust_daemon'
so = '$SCRIPT_DIR/libpatch_rust.so'

target_base = get_vma_base(pid, 'rust_daemon')
target_off = get_symbol_off(exe, 'rust_get_rate_limit')
target_vaddr = target_base + target_off

patch_base = get_vma_base(pid, 'libpatch_rust.so')
patch_off = get_symbol_off(so, 'livepatch_rust_get_rate_limit')
patch_vaddr = patch_base + patch_off

print(f'{hex(target_vaddr)} {hex(patch_vaddr)}')
")

TARGET_VADDR=$(echo "$ADDRS" | awk '{print $1}')
PATCH_VADDR=$(echo "$ADDRS" | awk '{print $2}')
echo "[+] Rust target function : rust_get_rate_limit           -> $TARGET_VADDR"
echo "[+] Rust patch function  : livepatch_rust_get_rate_limit -> $PATCH_VADDR"

# Step 7: Apply livepatch via ulp_ctl
echo -e "\n${YELLOW}>>> [Step 7] Applying livepatch via ulp_ctl...${NC}"
"$ULP_CTL" apply "$RUST_PID" "rust_patch" "rust_get_rate_limit" "$TARGET_VADDR" "$PATCH_VADDR" 16

echo -e "\n[*] Active livepatches (/proc/ulp_patches):"
cat /proc/ulp_patches

# Step 8: Query livepatched service
echo -e "\n${YELLOW}>>> [Step 8] Querying livepatched Rust service...${NC}"
RESP=$("$SCRIPT_DIR/rust_daemon" --query)
echo -e "Service Response: ${GREEN}$RESP${NC}"
if [[ "$RESP" != *"LIVEPATCHED"* ]]; then
    echo -e "${RED}[FAIL] Livepatch did not take effect! Got: $RESP${NC}"
    exit 1
fi
echo -e "${GREEN}[+] LIVEPATCH VERIFIED: Rust function successfully hotpatched at runtime!${NC}"

# Step 9: Revert livepatch
echo -e "\n${YELLOW}>>> [Step 9] Reverting livepatch via ulp_ctl...${NC}"
"$ULP_CTL" revert "$RUST_PID" "$TARGET_VADDR"

echo -e "\n[*] Active livepatches post-revert (/proc/ulp_patches):"
cat /proc/ulp_patches

# Step 10: Query baseline restoration
echo -e "\n${YELLOW}>>> [Step 10] Querying Rust service after revert...${NC}"
RESP=$("$SCRIPT_DIR/rust_daemon" --query)
echo -e "Service Response: ${BLUE}$RESP${NC}"
if [[ "$RESP" != *"UNPATCHED"* ]]; then
    echo -e "${RED}[FAIL] Baseline not restored! Got: $RESP${NC}"
    exit 1
fi
echo -e "${GREEN}[+] REVERT VERIFIED: Original Rust code restored cleanly!${NC}"

echo -e "\n${GREEN}======================================================================${NC}"
echo -e "${GREEN}>>> EXAMPLE 3 COMPLETED SUCCESSFULLY: ALL CHECKS PASSED!            <<<${NC}"
echo -e "${GREEN}======================================================================${NC}"
