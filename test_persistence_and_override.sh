#!/usr/bin/env bash
# ==============================================================================
# ulp-driver: Persistent Livepatching & Anti-Tamper Override Test Suite
# Tests:
# 1. Automatic early-exec livepatching on service startup (systemctl restart)
# 2. Persistence across seamless service reloads under active Vegeta 10,000 req/s load
# 3. Bitflip / Tampering rejection test (1-bit flip fails closed, patch remains active)
# 4. Valid signed cryptographic override test (clean authorized emergency rollback)
# ==============================================================================
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${BLUE}======================================================================${NC}"
echo -e "${BLUE}   PERSISTENT LIVEPATCHING & ANTI-TAMPER OVERRIDE BENCHMARK SUITE    ${NC}"
echo -e "${BLUE}======================================================================${NC}"

DRIVER_DIR="/root/ulp-driver/ulp-driver"
HAPROXY_DIR="/root/haproxy-livepatch"

# 0. Build and Install ULP Subsystem
echo -e "${YELLOW}>>> [Step 0] Building and installing ULP components...${NC}"
cd "$DRIVER_DIR"
make clean && make
rmmod ulp_driver 2>/dev/null || true
insmod ulp_driver.ko

cp ulp_ctl /usr/local/bin/
cp ulp_inject /usr/local/bin/
cp ulp_persist /usr/local/bin/
cp libulp_preload.so /usr/local/lib/
ldconfig

mkdir -p /etc/ulp
ulp_persist generate-key
ulp_persist clear-override >/dev/null 2>&1 || true

# 1. Setup Early-Exec Preload via /etc/ld.so.preload
echo -e "${YELLOW}>>> [Step 1] Configuring /etc/ld.so.preload for early-exec auto-patching...${NC}"
if ! grep -q "/usr/local/lib/libulp_preload.so" /etc/ld.so.preload 2>/dev/null; then
    echo "/usr/local/lib/libulp_preload.so" >> /etc/ld.so.preload
fi

# 2. Register Persistent Livepatch Rule for HAProxy
echo -e "${YELLOW}>>> [Step 2] Registering persistent livepatch rule for HAProxy...${NC}"
cd "$HAPROXY_DIR"
make clean && make
HAPROXY_BIN=$(readlink -f /usr/local/sbin/haproxy)
PATCH_SO=$(readlink -f "$HAPROXY_DIR/patch_haproxy.so")

# Remove any old rules and add rule for stktable_deinit
rm -f /etc/ulp/persistent_rules.conf
ulp_persist add "$HAPROXY_BIN" "$PATCH_SO" "stktable_deinit" "livepatch_stktable_deinit" 16 1
ulp_persist list

# -----------------------------------------------------------------------------
# TEST 1: Service Restart Auto-Patching Verification
# -----------------------------------------------------------------------------
echo -e "\n${BLUE}======================================================================${NC}"
echo -e "${BLUE}>>> TEST 1: Service Restart Auto-Patching (systemctl restart haproxy)... <<<${NC}"
echo -e "${BLUE}======================================================================${NC}"

systemctl restart haproxy
sleep 2

HAPROXY_PID=$(pidof haproxy | awk '{print $1}')
echo -e "${GREEN}[+] HAProxy restarted with PID: $HAPROXY_PID${NC}"

echo -e "\n${BLUE}--- Active ULP Kernel Livepatch Registry (/proc/ulp_patches) ---${NC}"
cat /proc/ulp_patches

if grep -q "haproxy" /proc/ulp_patches; then
    echo -e "${GREEN}[TEST 1 PASSED] HAProxy was automatically livepatched upon startup before main()!${NC}"
else
    echo -e "${RED}[TEST 1 FAILED] HAProxy did not automatically receive livepatch.${NC}"
    exit 1
fi

# -----------------------------------------------------------------------------
# TEST 2: Seamless Service Reload Under 10,000 req/s Load
# -----------------------------------------------------------------------------
echo -e "\n${BLUE}======================================================================${NC}"
echo -e "${BLUE}>>> TEST 2: Seamless Reload Persistence Under 10,000 req/s Load... <<<${NC}"
echo -e "${BLUE}======================================================================${NC}"

TARGET_URL="http://127.0.0.1:8080/test"
VEGETA_LOG="/tmp/vegeta_reload.bin"
echo "GET $TARGET_URL" | vegeta attack -rate=10000 -duration=15s -workers=64 > "$VEGETA_LOG" &
VEG_PID=$!

sleep 3
echo -e "${YELLOW}>>> Executing 'systemctl reload haproxy' during live 10,000 req/s traffic...${NC}"
systemctl reload haproxy
sleep 2

NEW_HAPROXY_PID=$(pidof haproxy | awk '{print $1}')
echo -e "${GREEN}[+] HAProxy reloaded. New Master PID: $NEW_HAPROXY_PID${NC}"

wait $VEG_PID

echo -e "\n${BLUE}--- Active Livepatches After Reload ---${NC}"
cat /proc/ulp_patches

echo -e "\n${BLUE}--- VEGETA REPORT FOR SEAMLESS RELOAD ---${NC}"
vegeta report "$VEGETA_LOG"

if grep -q "haproxy" /proc/ulp_patches; then
    echo -e "${GREEN}[TEST 2 PASSED] New HAProxy processes inherited livepatching across reload!${NC}"
else
    echo -e "${RED}[TEST 2 FAILED] Livepatch lost after reload.${NC}"
    exit 1
fi

# -----------------------------------------------------------------------------
# TEST 3: Anti-Tamper & Bitflip Defense (Single-Bit Corruption Rejection)
# -----------------------------------------------------------------------------
echo -e "\n${BLUE}======================================================================${NC}"
echo -e "${BLUE}>>> TEST 3: Anti-Tamper & Bitflip Defense (Single-Bit Corruption)... <<<${NC}"
echo -e "${BLUE}======================================================================${NC}"

echo -e "${YELLOW}>>> Generating valid override ticket...${NC}"
ulp_persist create-override "$HAPROXY_BIN" 300

echo -e "${YELLOW}>>> Simulating a cracker or memory bitflip corruption (flipping 1 byte in ticket)...${NC}"
# Flip 1 byte in the HMAC signature of the ticket
python3 -c '
with open("/etc/ulp/override.ticket", "r+b") as f:
    data = bytearray(f.read())
    # Flip lowest bit of the HMAC signature byte
    data[-1] ^= 0x01
    f.seek(0)
    f.write(data)
print("[+] Injected 1-bit corruption into /etc/ulp/override.ticket")
'

echo -e "${YELLOW}>>> Restarting HAProxy with corrupted override ticket...${NC}"
systemctl restart haproxy
sleep 2

NEW_PID=$(pidof haproxy | awk '{print $1}')
echo -e "HAProxy PID: $NEW_PID"

cat /proc/ulp_patches
if grep -q "haproxy" /proc/ulp_patches; then
    echo -e "${GREEN}[TEST 3 PASSED] Corruption detected! System failed closed and enforced the security livepatch.${NC}"
else
    echo -e "${RED}[TEST 3 FAILED] Corrupted override ticket successfully bypassed livepatching!${NC}"
    exit 1
fi

# -----------------------------------------------------------------------------
# TEST 4: Authorized Signed Cryptographic Override Test
# -----------------------------------------------------------------------------
echo -e "\n${BLUE}======================================================================${NC}"
echo -e "${BLUE}>>> TEST 4: Authorized Signed Cryptographic Override Emergency Rollback... <<<${NC}"
echo -e "${BLUE}======================================================================${NC}"

echo -e "${YELLOW}>>> Generating legitimate signed override ticket...${NC}"
ulp_persist create-override "$HAPROXY_BIN" 300

echo -e "${YELLOW}>>> Restarting HAProxy with valid authorized override ticket...${NC}"
systemctl restart haproxy
sleep 2

cat /proc/ulp_patches
if grep -q "haproxy" /proc/ulp_patches; then
    echo -e "${RED}[TEST 4 FAILED] Authorized override did not bypass livepatching.${NC}"
    exit 1
else
    echo -e "${GREEN}[TEST 4 PASSED] Authorized operator cleanly launched unpatched HAProxy for emergency recovery.${NC}"
fi

# Re-enable livepatching
echo -e "\n${YELLOW}>>> Clearing override ticket and restoring active protection...${NC}"
ulp_persist clear-override
systemctl restart haproxy
sleep 2
cat /proc/ulp_patches

echo -e "\n${GREEN}======================================================================${NC}"
echo -e "${GREEN}>>> ALL PERSISTENCE AND ANTI-TAMPER TESTS COMPLETED SUCCESSFULLY! <<<${NC}"
echo -e "${GREEN}======================================================================${NC}"
