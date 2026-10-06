#!/usr/bin/env bash
# ==============================================================================
# Comprehensive Automated Test Battery for Enterprise Hardened x86_64 ULP Driver:
# Monotonic Ascending Scope Verification (Mode 0 -> Mode 1 -> Mode 2 -> Mode 3),
# DAC Boundaries, Clean VMA Locking, Futex Safety Gates,
# Active Thread Quiescence (func_len >= 16), Emergency Scope 0 Rollback,
# Creator UID Ownership Authorization, Native ulp_inject, and Immutable Ratchet
# ==============================================================================
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m'

PASSED_COUNT=0
FAILED_COUNT=0

assert_success() {
    local desc="$1"
    shift
    echo -n "  Testing: $desc ... "
    if "$@"; then
        echo -e "${GREEN}[PASS]${NC}"
        PASSED_COUNT=$((PASSED_COUNT + 1))
    else
        echo -e "${RED}[FAIL]${NC}"
        FAILED_COUNT=$((FAILED_COUNT + 1))
    fi
}

assert_failure() {
    local desc="$1"
    shift
    echo -n "  Testing: $desc ... "
    if "$@" 2>/dev/null; then
        echo -e "${RED}[FAIL (Expected failure but succeeded)]${NC}"
        FAILED_COUNT=$((FAILED_COUNT + 1))
    else
        echo -e "${GREEN}[PASS (Correctly rejected)]${NC}"
        PASSED_COUNT=$((PASSED_COUNT + 1))
    fi
}

echo -e "${BLUE}=== [1/7] Setting up Test Environment, Users, and Dummy Daemons ===${NC}"

# Recompile driver & tools
cd "$(dirname "$(readlink -f "$0")")"
make clean && make
rmmod ulp_driver 2>/dev/null || true
# dev_mode=1 bypasses the maintenance-window arming gate so suites 0-2 can test scope checks in isolation
insmod ulp_driver.ko dev_mode=1 2>/dev/null || true
# /dev/ulp is created 0600; scope 1 needs unprivileged users to reach the ioctl
chmod 666 /dev/ulp

# Install ulp_ctl and ulp_inject globally
install -m 755 ulp_ctl /usr/local/bin/ulp_ctl
install -m 755 ulp_inject /usr/local/bin/ulp_inject
ULP_CTL="/usr/local/bin/ulp_ctl"
ULP_INJECT="/usr/local/bin/ulp_inject"

# Setup test users alice (1001) and bob (1002)
useradd -u 1001 -m alice 2>/dev/null || true
useradd -u 1002 -m bob 2>/dev/null || true

TEST_DIR="/tmp/ulp_test_harness"
rm -rf "$TEST_DIR"
mkdir -p "$TEST_DIR"
chmod 777 "$TEST_DIR"

# Compile test dummy app with an aligned futex variable and signal toggler
cat << 'EOF' > "$TEST_DIR/dummy_target.c"
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdint.h>
#include <signal.h>
#include <sys/prctl.h>

volatile uint32_t g_test_futex = 0; // 0 = unlocked, 1 = locked

__attribute__((noinline))
int get_metric(void) {
    return 100;
}

void sig_handler(int sig) {
    if (sig == SIGUSR1) g_test_futex = 1; // lock
    if (sig == SIGUSR2) g_test_futex = 0; // unlock
}

int main(int argc, char **argv) {
    signal(SIGUSR1, sig_handler);
    signal(SIGUSR2, sig_handler);
    if (argc > 1)
        prctl(PR_SET_DUMPABLE, 0); /* like a setuid binary or a daemon that dropped privileges */
    while(1) {
        usleep(100000);
    }
    return 0;
}
EOF

# Compile patch payload
cat << 'EOF' > "$TEST_DIR/patch_metric.c"
#include <stdio.h>

__attribute__((noinline))
int livepatch_get_metric(void) {
    return 999;
}
EOF

gcc -O0 -no-pie -fno-omit-frame-pointer -falign-functions=16 "$TEST_DIR/dummy_target.c" -o "$TEST_DIR/dummy_bin"
gcc -shared -fPIC -O0 "$TEST_DIR/patch_metric.c" -o "$TEST_DIR/patch_metric.so"
chmod 777 "$TEST_DIR/dummy_bin" "$TEST_DIR/patch_metric.so"

killall dummy_bin 2>/dev/null || true

# Launch dummy processes for root, alice, and bob
su - alice -c "$TEST_DIR/dummy_bin &"
su - bob -c "$TEST_DIR/dummy_bin &"
su - alice -c "$TEST_DIR/dummy_bin nodump &"
$TEST_DIR/dummy_bin &
sleep 1

ALICE_PID=$(pgrep -u alice -f "dummy_bin$" | head -n 1)
ALICE_NODUMP_PID=$(pgrep -u alice -f "dummy_bin nodump" | head -n 1)
BOB_PID=$(pgrep -u bob dummy_bin | head -n 1)
ROOT_PID=$(pgrep -u root dummy_bin | head -n 1)

echo "Active test processes: Alice PID=$ALICE_PID | Bob PID=$BOB_PID | Root PID=$ROOT_PID"

# Calculate function target and patch addresses
TARGET_ADDR=$(nm "$TEST_DIR/dummy_bin" | grep -w "get_metric" | awk '{print "0x"$1}')
FUTEX_ADDR=$(nm "$TEST_DIR/dummy_bin" | grep -w "g_test_futex" | awk '{print "0x"$1}')
FUNC_LEN=64

# Inject patch .so via native sub-millisecond ulp_inject
inject_payload() {
    local pid="$1"
    $ULP_INJECT "$pid" "$TEST_DIR/patch_metric.so" >/dev/null 2>&1 || true
}

inject_payload "$ALICE_PID"
inject_payload "$BOB_PID"
inject_payload "$ROOT_PID"
inject_payload "$ALICE_NODUMP_PID"

get_patch_addr() {
    local pid="$1"
    local base=$(grep "patch_metric.so" /proc/"$pid"/maps | head -n 1 | awk '{print $1}' | cut -d- -f1)
    local off=$(nm -D "$TEST_DIR/patch_metric.so" | grep -w "livepatch_get_metric" | awk '{print $1}')
    python3 -c "print(hex(0x${base} + 0x${off}))"
}

ALICE_PATCH_ADDR=$(get_patch_addr "$ALICE_PID")
BOB_PATCH_ADDR=$(get_patch_addr "$BOB_PID")
ROOT_PATCH_ADDR=$(get_patch_addr "$ROOT_PID")
ALICE_NODUMP_PATCH_ADDR=$(get_patch_addr "$ALICE_NODUMP_PID")

# ==============================================================================
# [Suite 1]: Mode 0 (ULP_SCOPE_DISABLED) & Emergency Rollback
# ==============================================================================
echo -e "\n${BLUE}=== [2/7] Test Suite: Mode 0 (ULP_SCOPE_DISABLED) & Emergency Rollback ===${NC}"
sysctl -w kernel.ulp_scope=0 >/dev/null

assert_failure "Mode 0: New apply requests rejected while disabled" \
    $ULP_CTL apply "$ROOT_PID" "new_patch" "get_metric" "$TARGET_ADDR" "$ROOT_PATCH_ADDR" "$FUNC_LEN"

assert_failure "Mode 0: Alice cannot apply while disabled" \
    su - alice -c "$ULP_CTL apply $ALICE_PID test_patch get_metric $TARGET_ADDR $ALICE_PATCH_ADDR $FUNC_LEN"

# ==============================================================================
# [Suite 2]: Mode 1 (ULP_SCOPE_USER_SAME_UID & Ownership Verification)
# ==============================================================================
echo -e "\n${BLUE}=== [3/7] Test Suite: Mode 1 (ULP_SCOPE_USER_SAME_UID & Ownership Verification) ===${NC}"
sysctl -w kernel.ulp_scope=1 >/dev/null

assert_success "Mode 1: Alice CAN livepatch Alice's own process (quiescence len=$FUNC_LEN)" \
    su - alice -c "$ULP_CTL apply $ALICE_PID test_patch get_metric $TARGET_ADDR $ALICE_PATCH_ADDR $FUNC_LEN"

assert_failure "Mode 1: Alice CANNOT livepatch Bob's process (Cross-user blocked)" \
    su - alice -c "$ULP_CTL apply $BOB_PID test_attack get_metric $TARGET_ADDR $BOB_PATCH_ADDR $FUNC_LEN"

assert_failure "Mode 1: Alice CANNOT livepatch Root's process (Privilege escalation blocked)" \
    su - alice -c "$ULP_CTL apply $ROOT_PID test_attack get_metric $TARGET_ADDR $ROOT_PATCH_ADDR $FUNC_LEN"

assert_failure "Mode 1: Alice CANNOT livepatch her own non-dumpable process" \
    su - alice -c "$ULP_CTL apply $ALICE_NODUMP_PID test_attack get_metric $TARGET_ADDR $ALICE_NODUMP_PATCH_ADDR $FUNC_LEN"

assert_success "Mode 1: Root CAN livepatch Root process" \
    $ULP_CTL apply "$ROOT_PID" "root_patch" "get_metric" "$TARGET_ADDR" "$ROOT_PATCH_ADDR" "$FUNC_LEN"

assert_success "Mode 1: Root CAN livepatch Bob process (Admin override)" \
    $ULP_CTL apply "$BOB_PID" "admin_patch" "get_metric" "$TARGET_ADDR" "$BOB_PATCH_ADDR" "$FUNC_LEN"

# Visibility isolation check
echo -n "  Testing: Mode 1 Visibility isolation (/proc/ulp_patches) ... "
ALICE_COUNT=$(su - alice -c "cat /proc/ulp_patches" | grep -c "test_patch" || true)
BOB_COUNT=$(su - bob -c "cat /proc/ulp_patches" | grep -c "test_patch" || true)
ROOT_COUNT=$(cat /proc/ulp_patches | grep -c "test_patch\|root_patch\|admin_patch" || true)

if [ "$ALICE_COUNT" -eq 1 ] && [ "$BOB_COUNT" -eq 0 ] && [ "$ROOT_COUNT" -ge 2 ]; then
    echo -e "${GREEN}[PASS] (Alice saw 1 own patch, Bob saw 0, Root saw all)${NC}"
    PASSED_COUNT=$((PASSED_COUNT + 1))
else
    echo -e "${RED}[FAIL] (Alice=$ALICE_COUNT, Bob=$BOB_COUNT, Root=$ROOT_COUNT)${NC}"
    FAILED_COUNT=$((FAILED_COUNT + 1))
fi

assert_success "Mode 1: Alice CAN revert Alice's own livepatch" \
    su - alice -c "$ULP_CTL revert $ALICE_PID $TARGET_ADDR"

assert_failure "Mode 1: Bob CANNOT revert Root-applied patch on Bob's process (creator_uid authorization)" \
    su - bob -c "$ULP_CTL revert $BOB_PID $TARGET_ADDR"

assert_success "Mode 1: Root CAN revert Root-applied patch on Bob's process" \
    $ULP_CTL revert "$BOB_PID" "$TARGET_ADDR"

$ULP_CTL revert "$ROOT_PID" "$TARGET_ADDR" 2>/dev/null || true

# ==============================================================================
# [Suite 3]: Mode 2 (ULP_SCOPE_ROOT_ONLY - Default) & Memory/Futex Safety
# ==============================================================================
echo -e "\n${BLUE}=== [4/7] Test Suite: Mode 2 (ULP_SCOPE_ROOT_ONLY - Default) ===${NC}"
sysctl -w kernel.ulp_scope=2 >/dev/null

assert_success "Mode 2: Root CAN livepatch root process" \
    $ULP_CTL apply "$ROOT_PID" "root_patch" "get_metric" "$TARGET_ADDR" "$ROOT_PATCH_ADDR" "$FUNC_LEN"

assert_failure "Mode 2: Alice CANNOT livepatch even her own process (Root only)" \
    su - alice -c "$ULP_CTL apply $ALICE_PID user_patch get_metric $TARGET_ADDR $ALICE_PATCH_ADDR $FUNC_LEN"

assert_failure "Mode 2: Bob CANNOT livepatch his own process" \
    su - bob -c "$ULP_CTL apply $BOB_PID user_patch get_metric $TARGET_ADDR $BOB_PATCH_ADDR $FUNC_LEN"

$ULP_CTL revert "$ROOT_PID" "$TARGET_ADDR" 2>/dev/null || true

echo -e "\n${BLUE}=== [5/7] Test Suite: Clean VMA & Memory Safety Validation ===${NC}"

assert_failure "VMA: Reject patching non-existent / invalid memory (0x1000)" \
    $ULP_CTL apply "$ROOT_PID" "invalid_vma" "func" 0x1000 "$ROOT_PATCH_ADDR" "$FUNC_LEN"

assert_failure "VMA: Reject patching writable/non-executable heap address" \
    $ULP_CTL apply "$ROOT_PID" "non_exec_vma" "func" "$FUTEX_ADDR" "$ROOT_PATCH_ADDR" "$FUNC_LEN"

echo -e "\n${BLUE}=== [6/7] Test Suite: Futex & Quiescence Gates (with func_len=$FUNC_LEN) ===${NC}"

# Set futex to LOCKED (val = 1) via signal
kill -SIGUSR1 "$ROOT_PID"
sleep 0.1

assert_failure "Futex: Reject livepatch when target futex is LOCKED (returns -EBUSY)" \
    $ULP_CTL apply "$ROOT_PID" "locked_futex_patch" "get_metric" "$TARGET_ADDR" "$ROOT_PATCH_ADDR" "$FUNC_LEN" "$FUTEX_ADDR"

# Release futex (val = 0) via signal
kill -SIGUSR2 "$ROOT_PID"
sleep 0.1

assert_success "Futex: Allow livepatch when target futex is UNLOCKED & quiescent" \
    $ULP_CTL apply "$ROOT_PID" "unlocked_futex_patch" "get_metric" "$TARGET_ADDR" "$ROOT_PATCH_ADDR" "$FUNC_LEN" "$FUTEX_ADDR"

$ULP_CTL revert "$ROOT_PID" "$TARGET_ADDR" 2>/dev/null || true

# ==============================================================================
# [Suite 4]: Mode 3 (ULP_SCOPE_LOCKED - Immutable Ratchet & Module Pinning)
# ==============================================================================
echo -e "\n${BLUE}=== [7/7] Test Suite: Mode 3 (ULP_SCOPE_LOCKED - Immutable Ratchet & rmmod block) ===${NC}"
# Production semantics from here on: no dev_mode, so the ratchet and module pinning apply
echo N > /sys/module/ulp_driver/parameters/dev_mode
sysctl -w kernel.ulp_scope=3 >/dev/null

assert_failure "Mode 3: Root CANNOT livepatch without an armed maintenance window" \
    $ULP_CTL apply "$ROOT_PID" "locked_patch" "get_metric" "$TARGET_ADDR" "$ROOT_PATCH_ADDR" "$FUNC_LEN"

assert_failure "Mode 3: Alice CANNOT livepatch while locked" \
    su - alice -c "$ULP_CTL apply $ALICE_PID user_patch get_metric $TARGET_ADDR $ALICE_PATCH_ADDR $FUNC_LEN"

assert_failure "Mode 3: Ratchet prevents lowering scope from 3 to 2" \
    sysctl -w kernel.ulp_scope=2

assert_failure "Mode 3: Ratchet prevents lowering scope from 3 to 1" \
    sysctl -w kernel.ulp_scope=1

assert_failure "Mode 3: Ratchet prevents lowering scope from 3 to 0" \
    sysctl -w kernel.ulp_scope=0

CURRENT_SCOPE=$(sysctl -n kernel.ulp_scope)
echo -n "  Testing: Final scope remains locked at 3 ... "
if [ "$CURRENT_SCOPE" -eq 3 ]; then
    echo -e "${GREEN}[PASS] ($CURRENT_SCOPE == 3)${NC}"
    PASSED_COUNT=$((PASSED_COUNT + 1))
else
    echo -e "${RED}[FAIL] ($CURRENT_SCOPE != 3)${NC}"
    FAILED_COUNT=$((FAILED_COUNT + 1))
fi

assert_failure "Mode 3: rmmod blocked due to permanent module pinning" rmmod ulp_driver

$ULP_CTL revert "$ROOT_PID" "$TARGET_ADDR" 2>/dev/null || true

# Cleanup
killall dummy_bin 2>/dev/null || true
rm -rf "$TEST_DIR"

echo -e "\n${BLUE}======================================================================${NC}"
echo -e "${BLUE}Test Battery Summary: Total Passed: ${GREEN}${PASSED_COUNT}${BLUE} | Total Failed: ${RED}${FAILED_COUNT}${NC}"
echo -e "${BLUE}======================================================================${NC}"

if [ "$FAILED_COUNT" -eq 0 ]; then
    exit 0
else
    exit 1
fi
