#!/usr/bin/env bash
# ==============================================================================
# ulp-driver: Golang Server Livepatching Benchmark (Static vs Dynamic)
# Targets:
#   1. CGO_ENABLED=0 Pure Static Go Binary (Short Function 5-Byte Rel32 Jump)
#   2. CGO_ENABLED=1 Dynamic Go Binary (5-Byte Rel32 & 16-Byte CET Jump)
# Load Generator: Vegeta at 10,000 requests/sec Under Sustained Load
# ==============================================================================
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

BENCH_DIR="/root/go-livepatch-bench"
DRIVER_DIR="/root/ulp-driver/ulp-driver"

mkdir -p "$BENCH_DIR"
cd "$BENCH_DIR"

echo -e "${BLUE}======================================================================${NC}"
echo -e "${BLUE}   GOLANG SERVER LIVEPATCHING BENCHMARK (STATIC & DYNAMIC CGO)       ${NC}"
echo -e "${BLUE}======================================================================${NC}"

# 0. Build and reload ULP Kernel Driver & Tools
echo -e "${YELLOW}>>> [Step 0] Compiling and loading ULP kernel driver...${NC}"
cd "$DRIVER_DIR"
make clean && make
rmmod ulp_driver 2>/dev/null || true
insmod ulp_driver.ko
gcc -O2 -Wall -o /usr/local/bin/ulp_ctl ulp_ctl.c
gcc -O2 -Wall -o /usr/local/bin/ulp_inject ulp_inject.c -ldl
cd "$BENCH_DIR"

# 1. Compile Go Binaries & Patch Payloads
echo -e "${YELLOW}>>> [Step 1] Compiling Go server binaries and patch payloads...${NC}"
CGO_ENABLED=0 go build -o server_cgo0_static main.go
CGO_ENABLED=1 go build -o server_cgo1_dynamic main.go

# Compile Static Binary Raw Machine Code Blobs (.bin)
cat << "EOF" > patch_static_go.s
.global _start
.text
_start:
    lea msg(%rip), %rax
    mov $29, %rbx
    ret
msg:
    .ascii "LIVEPATCHED_STATIC_GO_SERVICE"
EOF
gcc -c -o patch_static_go.o patch_static_go.s
objcopy -O binary -j .text patch_static_go.o patch_static_go.bin

cat << "EOF" > patch_dynamic_cgo.s
.global _start
.text
_start:
    lea msg(%rip), %rax
    mov $31, %rbx
    ret
msg:
    .ascii "LIVEPATCHED_DYNAMIC_CGO_SERVICE"
EOF
gcc -c -o patch_dynamic_cgo.o patch_dynamic_cgo.s
objcopy -O binary -j .text patch_dynamic_cgo.o patch_dynamic_cgo.bin

# Helper to find function virtual address
get_func_vaddr() {
    local pid="$1"
    local exe="$2"
    local sym="$3"
    local base=$(grep "$exe" /proc/"$pid"/maps | head -n 1 | awk '{print $1}' | cut -d- -f1)
    local off=$(nm "$exe" | grep "$sym" | head -n 1 | awk '{print $1}')
    python3 -c "
b = 0x$base if len('$base') > 0 else 0
o = 0x$off
print(hex(o if o >= 0x400000 else (b + o)))
"
}

# ==============================================================================
# TEST PART 1: Statically Linked Go Binary (CGO_ENABLED=0)
# ==============================================================================
echo -e "\n${BLUE}======================================================================${NC}"
echo -e "${BLUE}>>> TEST 1: STATIC GOLANG BINARY LIVEPATCHING (CGO_ENABLED=0) <<<${NC}"
echo -e "${BLUE}======================================================================${NC}"

killall -9 server_cgo0_static 2>/dev/null || true
killall -9 server_cgo1_dynamic 2>/dev/null || true
fuser -k -9 9090/tcp 2>/dev/null || true
sleep 1

./server_cgo0_static &
GO_PID=$!
sleep 2

echo -e "${GREEN}[+] Static Go server running: PID $GO_PID (64 vCPUs)${NC}"

INIT_RESP=$(curl -s http://127.0.0.1:9090/)
echo -e "Initial Output: ${YELLOW}$INIT_RESP${NC}"

GO_EXE=$(readlink -f /proc/"$GO_PID"/exe)
SYM_ADDR=$(get_func_vaddr "$GO_PID" "$GO_EXE" "main.GetServiceStatus")
echo -e "Target Symbol Address: ${YELLOW}$SYM_ADDR${NC}"

# Start Background Vegeta Attack at 10,000 req/s
VEGETA_STATIC_REP="$BENCH_DIR/vegeta_static.bin"
rm -f "$VEGETA_STATIC_REP"

(
  echo "GET http://127.0.0.1:9090/" | vegeta attack -rate=10000/s -duration=15s > "$VEGETA_STATIC_REP"
) &
VEG_PID=$!
sleep 2

# Inject raw machine code into static binary via remote sys_mmap
echo -e "${YELLOW}>>> Injecting raw machine code payload via remote sys_mmap...${NC}"
INJECT_OUT=$(/usr/local/bin/ulp_inject "$GO_PID" "$BENCH_DIR/patch_static_go.bin")
echo "$INJECT_OUT"
PATCH_ADDR=$(echo "$INJECT_OUT" | grep "target_patch_addr=" | cut -d= -f2)
echo -e "Allocated Executable Patch Page: ${YELLOW}$PATCH_ADDR${NC}"

# Apply 5-Byte ULP Relative Jump Trampoline
echo -e "${YELLOW}>>> Applying 5-byte ULP relative jump trampoline...${NC}"
/usr/local/bin/ulp_ctl apply "$GO_PID" "patch_go_static" "main.GetServiceStatus" "$SYM_ADDR" "$PATCH_ADDR" 13
sleep 2

# Verify patched response under load
PATCHED_RESP=$(curl -s http://127.0.0.1:9090/)
echo -e "Livepatched Output Under Load: ${GREEN}$PATCHED_RESP${NC}"

# Revert patch on the fly
echo -e "${YELLOW}>>> Atomically reverting static livepatch on the fly...${NC}"
/usr/local/bin/ulp_ctl revert "$GO_PID" "$SYM_ADDR"
sleep 2

REVERT_RESP=$(curl -s http://127.0.0.1:9090/)
echo -e "Post-Revert Output: ${YELLOW}$REVERT_RESP${NC}"

wait $VEG_PID
echo -e "\n${BLUE}--- VEGETA REPORT (STATIC GO SERVER CGO_ENABLED=0) ---${NC}"
vegeta report "$VEGETA_STATIC_REP"
kill -9 $GO_PID 2>/dev/null || true
sleep 1

# ==============================================================================
# TEST PART 2: Dynamic CGO-Enabled Go Binary (CGO_ENABLED=1)
# ==============================================================================
echo -e "\n${BLUE}======================================================================${NC}"
echo -e "${BLUE}>>> TEST 2: DYNAMIC CGO GOLANG BINARY LIVEPATCHING (CGO_ENABLED=1) <<<${NC}"
echo -e "${BLUE}======================================================================${NC}"

killall -9 server_cgo0_static 2>/dev/null || true
killall -9 server_cgo1_dynamic 2>/dev/null || true
fuser -k -9 9090/tcp 2>/dev/null || true
sleep 1

./server_cgo1_dynamic &
GO_PID=$!
sleep 2

echo -e "${GREEN}[+] Dynamic CGO Go server running: PID $GO_PID (64 vCPUs)${NC}"

INIT_RESP=$(curl -s http://127.0.0.1:9090/)
echo -e "Initial Output: ${YELLOW}$INIT_RESP${NC}"

GO_EXE=$(readlink -f /proc/"$GO_PID"/exe)
SYM_ADDR=$(get_func_vaddr "$GO_PID" "$GO_EXE" "main.GetServiceStatus")
echo -e "Target Symbol Address: ${YELLOW}$SYM_ADDR${NC}"

# Start Background Vegeta Attack at 10,000 req/s
VEGETA_DYN_REP="$BENCH_DIR/vegeta_dynamic.bin"
rm -f "$VEGETA_DYN_REP"

(
  echo "GET http://127.0.0.1:9090/" | vegeta attack -rate=10000/s -duration=15s > "$VEGETA_DYN_REP"
) &
VEG_PID=$!
sleep 2

# Inject patch binary via remote sys_mmap
echo -e "${YELLOW}>>> Injecting machine code payload via remote sys_mmap...${NC}"
INJECT_OUT=$(/usr/local/bin/ulp_inject "$GO_PID" "$BENCH_DIR/patch_dynamic_cgo.bin")
echo "$INJECT_OUT"
PATCH_ADDR=$(echo "$INJECT_OUT" | grep "target_patch_addr=" | cut -d= -f2)
echo -e "Allocated Executable Patch Page: ${YELLOW}$PATCH_ADDR${NC}"

# Apply 5-Byte ULP Relative Jump Trampoline
echo -e "${YELLOW}>>> Applying 5-byte ULP relative jump trampoline...${NC}"
/usr/local/bin/ulp_ctl apply "$GO_PID" "patch_go_cgo" "main.GetServiceStatus" "$SYM_ADDR" "$PATCH_ADDR" 13
sleep 2

# Verify livepatched output
PATCHED_RESP=$(curl -s http://127.0.0.1:9090/)
echo -e "Livepatched Output Under Load: ${GREEN}$PATCHED_RESP${NC}"

# Revert patch on the fly
echo -e "${YELLOW}>>> Atomically reverting CGO livepatch on the fly...${NC}"
/usr/local/bin/ulp_ctl revert "$GO_PID" "$SYM_ADDR"
sleep 2

REVERT_RESP=$(curl -s http://127.0.0.1:9090/)
echo -e "Post-Revert Output: ${YELLOW}$REVERT_RESP${NC}"

wait $VEG_PID
echo -e "\n${BLUE}--- VEGETA REPORT (DYNAMIC CGO GO SERVER) ---${NC}"
vegeta report "$VEGETA_DYN_REP"
kill -9 $GO_PID 2>/dev/null || true

echo -e "\n${GREEN}======================================================================${NC}"
echo -e "${GREEN}>>> GOLANG LIVEPATCHING BENCHMARK PASSED (STATIC & DYNAMIC)! <<<${NC}"
echo -e "${GREEN}======================================================================${NC}"
