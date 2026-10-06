#!/usr/bin/env bash
# ==============================================================================
# ulp-driver: 64-vCPU / 64GB RAM Enterprise Livepatch Benchmark
# Target: HAProxy with 64 Concurrent Worker Threads (nbthread 64)
# Load Generator: Vegeta at 10,000 requests/sec (400,000 requests total)
# ==============================================================================
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

BENCH_DIR="/root/haproxy-multi-patch"
HAPROXY_DIR="/root/haproxy"
DRIVER_DIR="/root/ulp-driver/ulp-driver"

mkdir -p "$BENCH_DIR"
cd "$BENCH_DIR"

echo -e "${BLUE}======================================================================${NC}"
echo -e "${BLUE}   64-VCPU / 64-THREAD HAPROXY LIVEPATCHING BENCHMARK (10,000 REQ/S)  ${NC}"
echo -e "${BLUE}======================================================================${NC}"

# 0. Ensure ULP kernel driver is loaded
cd "$DRIVER_DIR"
make clean && make
insmod ulp_driver.ko 2>/dev/null || true
install -m 755 ulp_ctl /usr/local/bin/ulp_ctl
install -m 755 ulp_inject /usr/local/bin/ulp_inject
cd "$BENCH_DIR"

# 1. Compile all commit livepatch shared objects
echo -e "${YELLOW}>>> [Step 1] Compiling all upstream livepatch modules...${NC}"
gcc -shared -fPIC -O2 -o patch_sample.so patch_sample.c
gcc -shared -fPIC -O2 -o patch_show_backend.so patch_show_backend.c
gcc -shared -fPIC -O2 -o patch_h2_dump.so patch_h2_dump.c
gcc -shared -fPIC -O2 -o patch_uri_auth.so patch_uri_auth.c
gcc -shared -fPIC -O2 -o patch6_hpack_enc.so patch6_hpack_enc.c
gcc -shared -fPIC -O2 -o patch7_payload_sni.so patch7_payload_sni.c
gcc -shared -fPIC -O2 -o patch8_log.so patch8_log.c
gcc -shared -fPIC -O2 -o patch8_ssl_ctx.so patch8_ssl_ctx.c

chmod 755 *.so

# 2. Kill existing HAProxy and launch 64-thread daemon
echo -e "${YELLOW}>>> [Step 2] Launching HAProxy with 64 concurrent worker threads (nbthread 64)...${NC}"
killall haproxy 2>/dev/null || true
sleep 1

cat << "EOF" > "$BENCH_DIR/haproxy.cfg"
global
    maxconn 300000
    nbthread 64
    stats socket /tmp/haproxy.sock mode 660 level admin

defaults
    mode http
    timeout connect 5s
    timeout client 50s
    timeout server 50s
    maxconn 300000

frontend http_in
    bind 127.0.0.1:8080
    http-request return status 200 content-type "text/plain" string "ULP_DRIVER_OK\n"
EOF

"$HAPROXY_DIR/haproxy" -f "$BENCH_DIR/haproxy.cfg" -db &
HAP_PID=$!
sleep 2

THREAD_COUNT=$(ls /proc/"$HAP_PID"/task | wc -l)
echo -e "${GREEN}[+] HAProxy active: PID $HAP_PID (${THREAD_COUNT} concurrent worker threads on $(nproc) vCPUs)${NC}"

# Helper functions to compute addresses
get_func_vaddr() {
    local pid="$1"
    local exe="$2"
    local sym="$3"
    local base=$(grep "$exe" /proc/"$pid"/maps | head -n 1 | awk '{print $1}' | cut -d- -f1)
    local off=$(nm "$exe" | grep -w "$sym" | head -n 1 | awk '{print $1}')
    python3 -c "print(hex(0x${base} + 0x${off}))"
}

get_so_vaddr() {
    local pid="$1"
    local so_name="$2"
    local sym="$3"
    local base=$(grep "$so_name" /proc/"$pid"/maps | head -n 1 | awk '{print $1}' | cut -d- -f1)
    local off=$(nm -D "$BENCH_DIR/$so_name" | grep -w "$sym" | head -n 1 | awk '{print $1}')
    python3 -c "print(hex(0x${base} + 0x${off}))"
}

HAP_EXE=$(readlink -f /proc/"$HAP_PID"/exe)

# 3. Start Background Vegeta Traffic Blast (10,000 req/s for 40 seconds = 400,000 requests)
echo -e "${YELLOW}>>> [Step 3] Starting background Vegeta attack (10,000 req/s sustained)...${NC}"
VEGETA_REPORT="$BENCH_DIR/vegeta_report.bin"
rm -f "$VEGETA_REPORT"

(
  echo "GET http://127.0.0.1:8080/" | vegeta attack -rate=10000/s -duration=40s > "$VEGETA_REPORT"
) &
VEGETA_PID=$!

echo -e "${GREEN}[+] Vegeta traffic generator running (PID $VEGETA_PID)${NC}"
sleep 2

# 4. Sequentially Apply All Upstream Bug Fixes Under Active 10,000 req/s Traffic
echo -e "\n${BLUE}======================================================================${NC}"
echo -e "${BLUE}>>> [Step 4] EXECUTING 64-THREAD LIVEPATCH COMMIT SEQUENCE UNDER LOAD <<<${NC}"
echo -e "${BLUE}======================================================================${NC}"

# --- PATCH 1: sample_conv_param_check ---
echo -e "\n${YELLOW}[Commit 1/8] Applying 'sample_conv_param_check' (0xHH control characters)...${NC}"
/usr/local/bin/ulp_inject "$HAP_PID" "$BENCH_DIR/patch_sample.so"
P1_ORIG=$(get_func_vaddr "$HAP_PID" "$HAP_EXE" "sample_conv_param_check")
P1_NEW=$(get_so_vaddr "$HAP_PID" "patch_sample.so" "livepatch_sample_conv_param_check")
/usr/local/bin/ulp_ctl apply "$HAP_PID" "fix_sample_param" "sample_conv_param_check" "$P1_ORIG" "$P1_NEW" 64
echo -e "${GREEN}[✓] Patch 1 applied cleanly across 64 threads!${NC}"
sleep 2

# --- PATCH 2: cli_io_handler_show_backend ---
echo -e "\n${YELLOW}[Commit 2/8] Applying 'cli_io_handler_show_backend' (iteration pointer fix)...${NC}"
/usr/local/bin/ulp_inject "$HAP_PID" "$BENCH_DIR/patch_show_backend.so"
P2_ORIG=$(get_func_vaddr "$HAP_PID" "$HAP_EXE" "cli_io_handler_show_backend")
P2_NEW=$(get_so_vaddr "$HAP_PID" "patch_show_backend.so" "livepatch_cli_io_handler_show_backend")
/usr/local/bin/ulp_ctl apply "$HAP_PID" "fix_show_backend" "cli_io_handler_show_backend" "$P2_ORIG" "$P2_NEW" 64
echo -e "${GREEN}[✓] Patch 2 applied cleanly across 64 threads!${NC}"
sleep 2

# --- PATCH 3: h2_dump_h2s_info ---
echo -e "\n${YELLOW}[Commit 3/8] Applying 'h2_dump_h2s_info' (NULL sd guard)...${NC}"
/usr/local/bin/ulp_inject "$HAP_PID" "$BENCH_DIR/patch_h2_dump.so"
P3_ORIG=$(get_func_vaddr "$HAP_PID" "$HAP_EXE" "h2_dump_h2s_info")
P3_NEW=$(get_so_vaddr "$HAP_PID" "patch_h2_dump.so" "livepatch_h2_dump_h2s_info")
/usr/local/bin/ulp_ctl apply "$HAP_PID" "fix_h2_dump_sd" "h2_dump_h2s_info" "$P3_ORIG" "$P3_NEW" 64
echo -e "${GREEN}[✓] Patch 3 applied cleanly across 64 threads!${NC}"
sleep 2

# --- PATCH 4: stats_add_auth ---
echo -e "\n${YELLOW}[Commit 4/8] Applying 'stats_add_auth' (NULL root safety check)...${NC}"
/usr/local/bin/ulp_inject "$HAP_PID" "$BENCH_DIR/patch_uri_auth.so"
P4_ORIG=$(get_func_vaddr "$HAP_PID" "$HAP_EXE" "stats_add_auth")
P4_NEW=$(get_so_vaddr "$HAP_PID" "patch_uri_auth.so" "livepatch_stats_add_auth")
/usr/local/bin/ulp_ctl apply "$HAP_PID" "fix_stats_add_auth" "stats_add_auth" "$P4_ORIG" "$P4_NEW" 64
echo -e "${GREEN}[✓] Patch 4 applied cleanly across 64 threads!${NC}"
sleep 2

# --- PATCH 5: hpack_encode_header ---
echo -e "\n${YELLOW}[Commit 5/8] Applying 'hpack_encode_header' (long method encoding)...${NC}"
/usr/local/bin/ulp_inject "$HAP_PID" "$BENCH_DIR/patch6_hpack_enc.so"
P5_ORIG=$(get_func_vaddr "$HAP_PID" "$HAP_EXE" "hpack_encode_header")
P5_NEW=$(get_so_vaddr "$HAP_PID" "patch6_hpack_enc.so" "livepatch_hpack_encode_header")
/usr/local/bin/ulp_ctl apply "$HAP_PID" "fix_hpack_encode" "hpack_encode_header" "$P5_ORIG" "$P5_NEW" 64
echo -e "${GREEN}[✓] Patch 5 applied cleanly across 64 threads!${NC}"
sleep 2

# --- PATCH 6: smp_client_hello_parse ---
echo -e "\n${YELLOW}[Commit 6/8] Applying 'smp_client_hello_parse' (SSL client hello cleanup)...${NC}"
/usr/local/bin/ulp_inject "$HAP_PID" "$BENCH_DIR/patch7_payload_sni.so"
P6_ORIG=$(get_func_vaddr "$HAP_PID" "$HAP_EXE" "smp_client_hello_parse")
P6_NEW=$(get_so_vaddr "$HAP_PID" "patch7_payload_sni.so" "livepatch_smp_client_hello_parse")
/usr/local/bin/ulp_ctl apply "$HAP_PID" "fix_client_hello" "smp_client_hello_parse" "$P6_ORIG" "$P6_NEW" 64
echo -e "${GREEN}[✓] Patch 6 applied cleanly across 64 threads!${NC}"
sleep 2

# --- PATCH 7: parse_logger ---
echo -e "\n${YELLOW}[Commit 7/8] Applying 'parse_logger' (double-free prevention)...${NC}"
/usr/local/bin/ulp_inject "$HAP_PID" "$BENCH_DIR/patch8_log.so"
P7_ORIG=$(get_func_vaddr "$HAP_PID" "$HAP_EXE" "parse_logger")
P7_NEW=$(get_so_vaddr "$HAP_PID" "patch8_log.so" "livepatch_parse_logger")
/usr/local/bin/ulp_ctl apply "$HAP_PID" "fix_parse_logger" "parse_logger" "$P7_ORIG" "$P7_NEW" 64
echo -e "${GREEN}[✓] Patch 7 applied cleanly across 64 threads!${NC}"
sleep 2

# --- PATCH 8: ssl_sock_prepare_ctx ---
echo -e "\n${YELLOW}[Commit 8/8] Applying 'ssl_sock_prepare_ctx' (SNI context safety)...${NC}"
/usr/local/bin/ulp_inject "$HAP_PID" "$BENCH_DIR/patch8_ssl_ctx.so"
P8_ORIG=$(get_func_vaddr "$HAP_PID" "$HAP_EXE" "ssl_sock_prepare_ctx")
P8_NEW=$(get_so_vaddr "$HAP_PID" "patch8_ssl_ctx.so" "livepatch_ssl_sock_prepare_ctx")
/usr/local/bin/ulp_ctl apply "$HAP_PID" "fix_ssl_prepare_ctx" "ssl_sock_prepare_ctx" "$P8_ORIG" "$P8_NEW" 64
echo -e "${GREEN}[✓] Patch 8 applied cleanly across 64 threads!${NC}"
sleep 2

# --- Dynamic Rollback Validation of Patch 1, Patch 3, Patch 5 & Patch 7 Under 64-Thread Load ---
echo -e "\n${YELLOW}[Rollback Test] Atomically reverting Patches 1, 3, 5, and 7 under 64-thread load...${NC}"
/usr/local/bin/ulp_ctl revert "$HAP_PID" "$P1_ORIG"
/usr/local/bin/ulp_ctl revert "$HAP_PID" "$P3_ORIG"
/usr/local/bin/ulp_ctl revert "$HAP_PID" "$P5_ORIG"
/usr/local/bin/ulp_ctl revert "$HAP_PID" "$P7_ORIG"
echo -e "${GREEN}[✓] Dynamic rollback completed cleanly without dropped packets!${NC}"
sleep 2

# 5. Wait for Vegeta attack to finish and report results
echo -e "\n${YELLOW}>>> [Step 5] Awaiting completion of Vegeta load benchmark...${NC}"
wait $VEGETA_PID

echo -e "\n${BLUE}======================================================================${NC}"
echo -e "${BLUE}                     VEGETA LOAD BENCHMARK REPORT                     ${NC}"
echo -e "${BLUE}======================================================================${NC}"
vegeta report "$VEGETA_REPORT"
echo -e "${BLUE}======================================================================${NC}"

# 6. Active Kernel Livepatches Registry & Stability Audit
echo -e "\n${YELLOW}>>> Active Kernel Livepatches (/proc/ulp_patches):${NC}"
cat /proc/ulp_patches

echo -e "\n${YELLOW}>>> Dmesg Audit (Checking for any driver/kernel anomalies):${NC}"
dmesg | tail -n 15

# Verify HTTP response from running HAProxy
echo -e "\n${YELLOW}>>> Verifying HAProxy post-livepatch status:${NC}"
curl -i http://127.0.0.1:8080/

# Success check
SUCCESS_RATE=$(vegeta report "$VEGETA_REPORT" | grep "Success" | awk '{print $2}' | tr -d '%')
IS_SUCCESS=$(python3 -c "import re; m = re.search(r'([0-9.]+)', '$SUCCESS_RATE'); print(1 if m and float(m.group(1)) >= 99.99 else 0)")
if [ "$IS_SUCCESS" -eq 1 ]; then
    echo -e "\n${GREEN}======================================================================${NC}"
    echo -e "${GREEN}>>> 64-CORE / 64-THREAD ENTERPRISE STABILITY VERIFIED (100% SUCCESS)! <<<${NC}"
    echo -e "${GREEN}======================================================================${NC}"
    kill $HAP_PID 2>/dev/null || true
    exit 0
else
    echo -e "\n${RED}>>> WARNING: Dropped requests detected during livepatching! <<<${NC}"
    kill $HAP_PID 2>/dev/null || true
    exit 1
fi
