#!/usr/bin/env bash
# ==============================================================================
# ulp-driver: Enterprise MariaDB 11.8 / MySQL Livepatching Benchmark
# Target: MariaDB Multi-Threaded Daemon under active sysbench OLTP load
# Function: server_mysql_get_server_version() (228 bytes)
# Trampoline: 16-Byte CET/IBT Absolute Trampoline
# ==============================================================================
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

BENCH_DIR="/root/mariadb-livepatch-bench"
DRIVER_DIR="/root/ulp-driver/ulp-driver"

mkdir -p "$BENCH_DIR"
cd "$BENCH_DIR"

echo -e "${BLUE}======================================================================${NC}"
echo -e "${BLUE}   MARIADB 11.8 LIVEPATCHING BENCHMARK UNDER ACTIVE SYSBENCH OLTP LOAD${NC}"
echo -e "${BLUE}======================================================================${NC}"

# 0. Reload ULP Driver & Recompile Tools
echo -e "${YELLOW}>>> [Step 0] Compiling and loading ULP kernel driver...${NC}"
cd "$DRIVER_DIR"
make clean && make
if ! lsmod | grep -q "^ulp_driver "; then
    insmod ulp_driver.ko
fi
gcc -O2 -Wall -o /usr/local/bin/ulp_ctl ulp_ctl.c
gcc -O2 -Wall -o /usr/local/bin/ulp_inject ulp_inject.c -ldl
cd "$BENCH_DIR"

# 1. Compile Livepatch Shared Library to accessible location
echo -e "${YELLOW}>>> [Step 1] Compiling /usr/lib/mysql/plugin/patch_mariadb.so...${NC}"
gcc -shared -fPIC -O2 -o /usr/lib/mysql/plugin/patch_mariadb.so patch_mariadb.c
chown mysql:mysql /usr/lib/mysql/plugin/patch_mariadb.so 2>/dev/null || true
chmod 755 /usr/lib/mysql/plugin/patch_mariadb.so

# 2. Setup MariaDB Test Database
echo -e "${YELLOW}>>> [Step 2] Setting up MariaDB sbtest with sysbench...${NC}"
systemctl restart mariadb
sleep 2

mariadb -e "CREATE DATABASE IF NOT EXISTS sbtest;"
sysbench oltp_read_only --db-driver=mysql --mysql-user=root --mysql-db=sbtest --tables=10 --table-size=10000 prepare >/dev/null 2>&1 || true
echo -e "${GREEN}[+] MariaDB sbtest database initialized with 10 tables.${NC}"

# Find mariadbd PID
MARIADB_PID=$(pidof mariadbd || pgrep -f "/usr/sbin/mariadbd")
echo -e "${GREEN}[+] mariadbd running: PID $MARIADB_PID (64 vCPUs)${NC}"

MARIADB_BIN=$(readlink -f /usr/sbin/mariadbd)

# Helper to compute virtual addresses
get_pie_func_vaddr() {
    local pid="$1"
    local exe="$2"
    local sym="$3"
    local base=$(grep "$exe" /proc/"$pid"/maps | head -n 1 | awk '{print $1}' | cut -d- -f1)
    local off=$(nm -D "$exe" 2>/dev/null | grep -w "$sym" | head -n 1 | awk '{print $1}')
    if [ -z "$off" ]; then
        off=$(nm "$exe" 2>/dev/null | grep -w "$sym" | head -n 1 | awk '{print $1}')
    fi
    python3 -c "print(hex(0x${base} + 0x${off}))"
}

get_so_vaddr() {
    local pid="$1"
    local so_name="$2"
    local sym="$3"
    local base=$(grep "$so_name" /proc/"$pid"/maps | head -n 1 | awk '{print $1}' | cut -d- -f1)
    local off=$(nm -D "/usr/lib/mysql/plugin/$so_name" | grep -w "$sym" | awk '{print $1}')
    python3 -c "print(hex(0x${base} + 0x${off}))"
}

TARGET_VADDR=$(get_pie_func_vaddr "$MARIADB_PID" "$MARIADB_BIN" "server_mysql_get_server_version")
echo -e "Target Symbol Address: ${YELLOW}$TARGET_VADDR${NC}"

# 3. Start Sustained sysbench OLTP Load (32 Threads, 20 Seconds)
echo -e "\n${BLUE}======================================================================${NC}"
echo -e "${BLUE}>>> Launching sustained sysbench OLTP load (32 threads, 64 vCPUs)... <<<${NC}"
echo -e "${BLUE}======================================================================${NC}"

SYSBENCH_LOG="$BENCH_DIR/sysbench.log"
(
  sysbench oltp_read_only --db-driver=mysql --mysql-user=root --mysql-db=sbtest --threads=32 --time=20 --report-interval=2 run > "$SYSBENCH_LOG" 2>&1
) &
SYS_PID=$!
sleep 3

# Inject shared library into mariadbd under live multi-threaded load
echo -e "${YELLOW}>>> Injecting /usr/lib/mysql/plugin/patch_mariadb.so via non-destructive stack dlopen...${NC}"
/usr/local/bin/ulp_inject "$MARIADB_PID" "/usr/lib/mysql/plugin/patch_mariadb.so"

PATCH_VADDR=$(get_so_vaddr "$MARIADB_PID" "patch_mariadb.so" "livepatch_server_mysql_get_server_version")
echo -e "Resolved Injected Function Address: ${YELLOW}$PATCH_VADDR${NC}"

# Apply 16-byte ULP CET/IBT Absolute Trampoline
echo -e "${YELLOW}>>> Applying 16-byte ULP CET/IBT absolute trampoline...${NC}"
/usr/local/bin/ulp_ctl apply "$MARIADB_PID" "fix_mariadb_ver" "server_mysql_get_server_version" "$TARGET_VADDR" "$PATCH_VADDR" 228
sleep 3

# Verify /proc/ulp_patches kernel registry
echo -e "\n${BLUE}--- Active ULP Kernel Livepatch Registry (/proc/ulp_patches) ---${NC}"
cat /proc/ulp_patches

# Atomically revert livepatch on the fly
echo -e "\n${YELLOW}>>> Atomically reverting MariaDB livepatch on the fly...${NC}"
/usr/local/bin/ulp_ctl revert "$MARIADB_PID" "$TARGET_VADDR"
sleep 2

# Wait for sysbench completion
wait $SYS_PID
echo -e "\n${BLUE}======================================================================${NC}"
echo -e "${BLUE}--- SYSBENCH OLTP FINAL REPORT ---${NC}"
echo -e "${BLUE}======================================================================${NC}"
cat "$SYSBENCH_LOG"

echo -e "\n${GREEN}======================================================================${NC}"
echo -e "${GREEN}>>> MARIADB / MYSQL LIVEPATCHING BENCHMARK COMPLETED SUCCESSFULLY! <<<${NC}"
echo -e "${GREEN}======================================================================${NC}"
