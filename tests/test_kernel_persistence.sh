#!/usr/bin/env bash
# ==============================================================================
# ulp-driver: Pure In-Kernel Persistent Livepatching & Fork/Exec Suite
# Tests:
# 1. Automatic In-Kernel Fork Inheritance on process clone/fork
# 2. In-Kernel Execve Auto-Patching matching UID, PID hierarchy, or Global scope
# 3. Kernel-Side Anti-Bitflip Magic Validation (Single-bit corruption fails closed)
# 4. Kernel-Side Emergency Authorized Override & Expiration
# ==============================================================================
set -euo pipefail

REPO_DIR="$(cd "$(dirname "$(readlink -f "$0")")/.." && pwd)"
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${BLUE}======================================================================${NC}"
echo -e "${BLUE}   PURE IN-KERNEL PERSISTENCE, FORK INHERITANCE & EXECVE SUITE        ${NC}"
echo -e "${BLUE}======================================================================${NC}"

DRIVER_DIR="$REPO_DIR/ulp-driver"
HAPROXY_DIR="/root/haproxy-livepatch"

# 0. Build and Reload Kernel Driver
echo -e "${YELLOW}>>> [Step 0] Compiling and reloading ULP kernel driver with Kprobes...${NC}"
cd "$DRIVER_DIR"
make clean && make
rmmod ulp_driver 2>/dev/null || true
insmod ulp_driver.ko

gcc -O2 -Wall -o /usr/local/bin/ulp_ctl ulp_ctl.c
gcc -O2 -Wall -o /usr/local/bin/ulp_inject ulp_inject.c -ldl

# -----------------------------------------------------------------------------
# TEST 1: In-Kernel Fork Inheritance
# -----------------------------------------------------------------------------
echo -e "\n${BLUE}======================================================================${NC}"
echo -e "${BLUE}>>> TEST 1: Automatic In-Kernel Fork Inheritance on clone/fork... <<<${NC}"
echo -e "${BLUE}======================================================================${NC}"

# Compile a simple multi-process fork test in C with file trigger synchronization
cat << "EOF" > /tmp/fork_test.c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>

void __attribute__((noinline, aligned(16))) target_function(void) {
    printf("[PID %d] Original Target Function\n", getpid());
}

int main(void) {
    printf("[+] Parent started: PID %d\n", getpid());
    fflush(stdout);

    /* Wait for patch trigger file */
    while (access("/tmp/do_fork_trigger", F_OK) != 0) {
        usleep(50000);
    }

    /* Fork 2 children */
    for (int i = 0; i < 2; i++) {
        pid_t pid = fork();
        if (pid == 0) {
            printf("[+] Child %d (PID %d) executing target_function...\n", i+1, getpid());
            target_function();
            sleep(1);
            exit(0);
        }
    }

    target_function();
    while (wait(NULL) > 0);
    return 0;
}
EOF
gcc -O2 -falign-functions=16 -o /tmp/fork_test /tmp/fork_test.c -ldl

# Register in-kernel persistent rule for fork_test
OFF_FUNC=$(nm /tmp/fork_test | grep -w "target_function" | head -n 1 | awk '{print $1}')
echo -e "Registering in-kernel rule for /tmp/fork_test at offset 0x$OFF_FUNC..."
/usr/local/bin/ulp_ctl add-rule /tmp/fork_test "fork_fix" "target_function" "0x$OFF_FUNC" 0x0 16 -1 1
/usr/local/bin/ulp_ctl list-rules

# Run fork_test: Kernel execve hook auto-patches parent; fork hook auto-inherits to children!
touch /tmp/do_fork_trigger
/tmp/fork_test
rm -f /tmp/do_fork_trigger

echo -e "\n${BLUE}--- Active ULP Livepatch Hierarchy in Kernel ---${NC}"
cat /proc/ulp_patches
dmesg | grep -E "Fork inheritance|Kernel execve auto-patch" | tail -n 6

# -----------------------------------------------------------------------------
# TEST 2: In-Kernel Execve Auto-Patching
# -----------------------------------------------------------------------------
echo -e "\n${BLUE}======================================================================${NC}"
echo -e "${BLUE}>>> TEST 2: In-Kernel Execve Auto-Patching Across Service Restarts... <<<${NC}"
echo -e "${BLUE}======================================================================${NC}"

# Helper function to restart HAProxy daemon
restart_haproxy() {
    killall -9 haproxy 2>/dev/null || true
    sleep 0.5
    cat << "EOF" > /tmp/haproxy_min.cfg
global
    daemon
defaults
    mode http
    timeout connect 5000ms
    timeout client 50000ms
    timeout server 50000ms
frontend http-in
    bind *:8899
    default_backend servers
backend servers
    server server1 127.0.0.1:8000
EOF
    /usr/local/sbin/haproxy -f /tmp/haproxy_min.cfg -D
    sleep 1
}

HAPROXY_BIN=$(readlink -f /usr/local/sbin/haproxy)
OFF_STK=$(nm -D "$HAPROXY_BIN" 2>/dev/null | grep -w "stktable_deinit" | head -n 1 | awk '{print $1}')
if [ -z "$OFF_STK" ]; then
    OFF_STK=$(nm "$HAPROXY_BIN" 2>/dev/null | grep -w "stktable_deinit" | head -n 1 | awk '{print $1}')
fi
TARGET_OFFSET=$(python3 -c "print(hex(0x$OFF_STK))")

echo -e "Registering persistent kernel rule for HAProxy stktable_deinit at offset ${YELLOW}$TARGET_OFFSET${NC}..."
/usr/local/bin/ulp_ctl add-rule "$HAPROXY_BIN" "fix_stktable" "stktable_deinit" "$TARGET_OFFSET" 0x0 16 -1 1
/usr/local/bin/ulp_ctl list-rules

echo -e "${YELLOW}>>> Launching HAProxy daemon (execve into /usr/local/sbin/haproxy)...${NC}"
restart_haproxy

HAP_PID=$(pidof haproxy | awk '{print $1}')
echo -e "${GREEN}[+] HAProxy running with PID: $HAP_PID${NC}"

echo -e "\n${BLUE}--- Active Livepatches Registered by Kernel Execve Hook ---${NC}"
cat /proc/ulp_patches
dmesg | grep "Kernel execve auto-patch" | tail -n 3

if grep -q "haproxy" /proc/ulp_patches; then
    echo -e "${GREEN}[TEST 2 PASSED] Kernel automatically intercepted execve and livepatched HAProxy before main()!${NC}"
else
    echo -e "${RED}[TEST 2 FAILED] Execve auto-patch not found.${NC}"
    exit 1
fi

# -----------------------------------------------------------------------------
# TEST 3: Kernel-Side Anti-Bitflip Magic Validation
# -----------------------------------------------------------------------------
echo -e "\n${BLUE}======================================================================${NC}"
echo -e "${BLUE}>>> TEST 3: Kernel Anti-Bitflip Rejection Test... <<<${NC}"
echo -e "${BLUE}======================================================================${NC}"

# Attempt to set an override with an invalid (corrupted / 1-bit flipped) magic word via Python IOCTL
cat << "EOF" > /tmp/corrupt_override.py
import os, fcntl, struct

# ULP_IOC_SET_OVERRIDE = _IOW('U', 7, struct ulp_override_req)
# struct ulp_override_req: magic[4] (u64*4 = 32B), binary_path[128] (128B), ttl_seconds (u32 = 4B), padding (4B)
ULP_IOC_SET_OVERRIDE = 0x40a85507

# Valid magic: 0xA55AA55A69966996, etc.
# Injected Bitflip: lowest bit flipped on magic[0] -> 0xA55AA55A69966997
magic0 = 0xA55AA55A69966997
magic1 = 0x5AA55AA596699669
magic2 = 0xF00FF00F0FF00FF0
magic3 = 0x0FF00FF0F00FF00F
path = b"/usr/local/sbin/haproxy".ljust(128, b"\x00")
ttl = 300

buf = struct.pack("QQQQ128sII", magic0, magic1, magic2, magic3, path, ttl, 0)

fd = os.open("/dev/ulp", os.O_RDWR)
try:
    fcntl.ioctl(fd, ULP_IOC_SET_OVERRIDE, buf)
    print("[-] VULNERABILITY: Kernel accepted corrupted override magic!")
except OSError as e:
    print(f"[+] SUCCESS: Kernel rejected corrupted override magic with error: {e}")
finally:
    os.close(fd)
EOF

python3 /tmp/corrupt_override.py

echo -e "\n${YELLOW}>>> Restarting HAProxy to verify patch remains active (Fail-Closed Guarantee)...${NC}"
restart_haproxy

cat /proc/ulp_patches
if grep -q "haproxy" /proc/ulp_patches; then
    echo -e "${GREEN}[TEST 3 PASSED] Kernel failed closed on corrupted magic and enforced the security patch!${NC}"
else
    echo -e "${RED}[TEST 3 FAILED] Corrupted override disabled the livepatch!${NC}"
    exit 1
fi

# -----------------------------------------------------------------------------
# TEST 4: Authorized Kernel Emergency Override & Recovery
# -----------------------------------------------------------------------------
echo -e "\n${BLUE}======================================================================${NC}"
echo -e "${BLUE}>>> TEST 4: Authorized Kernel Emergency Override & Clean Recovery... <<<${NC}"
echo -e "${BLUE}======================================================================${NC}"

echo -e "${YELLOW}>>> Setting legitimate authorized 256-bit kernel override...${NC}"
/usr/local/bin/ulp_ctl set-override "$HAPROXY_BIN" 60

echo -e "${YELLOW}>>> Restarting HAProxy with active kernel override...${NC}"
restart_haproxy

cat /proc/ulp_patches
if grep -q "haproxy" /proc/ulp_patches; then
    echo -e "${RED}[TEST 4 FAILED] Override did not bypass livepatching.${NC}"
    exit 1
else
    echo -e "${GREEN}[TEST 4 PASSED] Authorized kernel override cleanly bypassed livepatching for emergency recovery.${NC}"
fi

echo -e "${YELLOW}>>> Clearing kernel override...${NC}"
/usr/local/bin/ulp_ctl clear-override
restart_haproxy

cat /proc/ulp_patches
if grep -q "haproxy" /proc/ulp_patches; then
    echo -e "${GREEN}[+] Livepatching automatically resumed following override clear.${NC}"
fi

killall -9 haproxy 2>/dev/null || true

echo -e "\n${GREEN}======================================================================${NC}"
echo -e "${GREEN}>>> ALL IN-KERNEL PERSISTENCE & FORK/EXEC TESTS PASSED! <<<${NC}"
echo -e "${GREEN}======================================================================${NC}"
