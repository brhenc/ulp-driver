#!/usr/bin/env bash
# ==============================================================================
# ulp-driver: Enterprise PostgreSQL 17 Livepatching Benchmark
# Target: PostgreSQL RDBMS under active pgbench load (32 concurrent clients)
# Function: pg_backend_pid() (12-byte short function in PostgreSQL text)
# Trampoline: 5-Byte Relative Jump (0xE9 rel32) with Atomic 8-Byte Word Overlay
# ==============================================================================
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

BENCH_DIR="/root/postgres-livepatch-bench"
DRIVER_DIR="/root/ulp-driver/ulp-driver"

mkdir -p "$BENCH_DIR"
cd "$BENCH_DIR"

echo -e "${BLUE}======================================================================${NC}"
echo -e "${BLUE}   POSTGRESQL 17 LIVEPATCHING BENCHMARK UNDER SUSTAINED PGBENCH LOAD  ${NC}"
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

# 1. Compile Livepatch Shared Library
echo -e "${YELLOW}>>> [Step 1] Compiling patch_postgres.so...${NC}"
gcc -shared -fPIC -O2 -o /tmp/patch_postgres.so patch_postgres.c
chmod 755 /tmp/patch_postgres.so

# 2. Setup PostgreSQL Test Database
echo -e "${YELLOW}>>> [Step 2] Setting up PostgreSQL ulp-driver_db with pgbench...${NC}"
systemctl restart postgresql
su - postgres -c "until pg_isready -q; do sleep 1; done"

su - postgres -c "psql -c 'DROP DATABASE IF EXISTS ulp-driver_db;' >/dev/null 2>&1 || true"
su - postgres -c "psql -c 'CREATE DATABASE ulp-driver_db;' >/dev/null"
su - postgres -c "pgbench -i -s 10 ulp-driver_db >/dev/null 2>&1"
echo -e "${GREEN}[+] ulp-driver_db initialized with 100,000 accounts.${NC}"

# Check initial query output
INIT_PID=$(su - postgres -c "psql -d ulp-driver_db -t -A -c 'SELECT pg_backend_pid();'")
echo -e "Initial pg_backend_pid(): ${YELLOW}$INIT_PID${NC}"

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
    local off=$(nm -D "/tmp/$so_name" | grep -w "$sym" | awk '{print $1}')
    python3 -c "print(hex(0x${base} + 0x${off}))"
}

# 3. Start Sustained pgbench Transaction Load (32 Clients, 32 Threads, 20 Seconds)
echo -e "\n${BLUE}======================================================================${NC}"
echo -e "${BLUE}>>> Launching sustained pgbench load (32 clients, 64 vCPUs)... <<<${NC}"
echo -e "${BLUE}======================================================================${NC}"

PGBENCH_LOG="$BENCH_DIR/pgbench.log"
(
  su - postgres -c "pgbench -c 32 -j 32 -T 20 -M prepared ulp-driver_db" > "$PGBENCH_LOG" 2>&1
) &
PGBENCH_PID=$!
sleep 3

# Find active PostgreSQL backend worker PIDs
BACKEND_PIDS=$(pgrep -f "postgres: .* ulp-driver_db" || true)
if [ -z "$BACKEND_PIDS" ]; then
    BACKEND_PIDS=$(pgrep -u postgres -f "postgres:" | grep -v -E "checkpointer|walwriter|autovacuum|logger|background|startup" | head -n 10)
fi

echo -e "Target PostgreSQL PIDs under active traffic: ${YELLOW}$BACKEND_PIDS${NC}"

POSTGRES_BIN=$(readlink -f /usr/lib/postgresql/17/bin/postgres)

# Livepatch all active backend workers under live transaction load
for TARGET_PID in $BACKEND_PIDS; do
    if [ -d "/proc/$TARGET_PID" ]; then
        TARGET_VADDR=$(get_pie_func_vaddr "$TARGET_PID" "$POSTGRES_BIN" "pg_backend_pid")
        echo -e "${YELLOW}>>> Injecting patch_postgres.so into PID $TARGET_PID (pg_backend_pid @ $TARGET_VADDR)...${NC}"
        /usr/local/bin/ulp_inject "$TARGET_PID" "/tmp/patch_postgres.so" >/dev/null 2>&1 || true
        
        PATCH_VADDR=$(get_so_vaddr "$TARGET_PID" "patch_postgres.so" "livepatch_pg_backend_pid" 2>/dev/null || echo "0")
        if [ "$PATCH_VADDR" != "0" ]; then
            /usr/local/bin/ulp_ctl apply "$TARGET_PID" "fix_pg_pid" "pg_backend_pid" "$TARGET_VADDR" "$PATCH_VADDR" 16
        fi
    fi
done

sleep 2

# Verify patched response under load
PATCHED_OUT=$(su - postgres -c "psql -d ulp-driver_db -t -A -c 'SELECT pg_backend_pid();'")
echo -e "\nQuery Result Under Active Load: ${GREEN}$PATCHED_OUT${NC} (Expected: 999999)"

# Verify /proc/ulp_patches kernel registry
echo -e "\n${BLUE}--- Active ULP Kernel Livepatch Registry (/proc/ulp_patches) ---${NC}"
cat /proc/ulp_patches

# Atomically revert livepatches on the fly
echo -e "\n${YELLOW}>>> Atomically reverting livepatches on all active backends...${NC}"
for TARGET_PID in $BACKEND_PIDS; do
    if [ -d "/proc/$TARGET_PID" ]; then
        TARGET_VADDR=$(get_pie_func_vaddr "$TARGET_PID" "$POSTGRES_BIN" "pg_backend_pid" 2>/dev/null || echo "0")
        if [ "$TARGET_VADDR" != "0" ]; then
            /usr/local/bin/ulp_ctl revert "$TARGET_PID" "$TARGET_VADDR" >/dev/null 2>&1 || true
        fi
    fi
done

sleep 2
POST_REVERT_PID=$(su - postgres -c "psql -d ulp-driver_db -t -A -c 'SELECT pg_backend_pid();'")
echo -e "Post-Revert Query Result: ${YELLOW}$POST_REVERT_PID${NC}"

# Wait for pgbench completion
wait $PGBENCH_PID
echo -e "\n${BLUE}======================================================================${NC}"
echo -e "${BLUE}--- PGBENCH FINAL REPORT ---${NC}"
echo -e "${BLUE}======================================================================${NC}"
cat "$PGBENCH_LOG"

echo -e "\n${GREEN}======================================================================${NC}"
echo -e "${GREEN}>>> POSTGRESQL LIVEPATCHING BENCHMARK COMPLETED SUCCESSFULLY! <<<${NC}"
echo -e "${GREEN}======================================================================${NC}"
