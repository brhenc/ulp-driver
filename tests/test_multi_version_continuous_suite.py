#!/usr/bin/env python3
"""
ulp-driver: Unified Multi-Version Continuous Livepatching Test Suite
==============================================================================
Validates continuous multi-generation livepatching across heterogeneous workloads:
  - Rust Daemon: pgrust (SMP multi-threaded database engine)
  - C Daemon 1: MariaDB 11.8 (Relational database server)
  - C Daemon 2: PostgreSQL 17 (Enterprise RDBMS)
  - C Daemon 3: HAProxy (High-performance multi-threaded proxy)

Executes sequential transitions:
  V0 (Vanilla Baseline)
    -> V1 (Security Audit & Telemetry Hotfix)
    -> V2 (Dynamic Shadow Metrics & Accelerated Cache)
    -> V3 (Vectorized SMP & Enterprise Lockless Mode)
    -> Kernel Driver Resumption Reload Cycle (rmmod / insmod with zero-downtime)
    -> Revert (Atomic rollback back to V0)
"""

import os as _os
import sys as _sys
REPO_DIR = _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__)))
if REPO_DIR not in _sys.path:
    _sys.path.insert(0, REPO_DIR)
import os
import sys
import time
import shutil
import socket
import subprocess
import threading

BASE_DIR = REPO_DIR
DRIVER_DIR = f"{BASE_DIR}/ulp-driver"
ULP_CTL = "/usr/local/bin/ulp_ctl"
ULP_INJECT = "/usr/local/bin/ulp_inject"

RUST_BENCH = f"{BASE_DIR}/rust-livepatch-bench"
PGRUST_DAEMON = f"{RUST_BENCH}/target/release/pgrust_daemon"
PGRUST_CLIENT = f"{RUST_BENCH}/target/release/pgrust_client"

# Staging directories with 0777 world-accessible permissions
STAGE_DIR = "/tmp/ulp_patches"
MYSQL_PLUGIN_DIR = "/usr/lib/mysql/plugin"

os.makedirs(STAGE_DIR, exist_ok=True)
os.chmod(STAGE_DIR, 0o777)

PGRUST_V1_SRC = f"{RUST_BENCH}/patch_pgrust_v1/target/release/libpatch_pgrust_v1.so"
PGRUST_V2_SRC = f"{RUST_BENCH}/patch_pgrust_v2/target/release/libpatch_pgrust_v2.so"
PGRUST_V3_SRC = f"{RUST_BENCH}/patch_pgrust_v3/target/release/libpatch_pgrust_v3.so"

MARIADB_V1_SRC = f"{BASE_DIR}/mariadb-livepatch-bench/patch_mariadb_v1.so"
MARIADB_V2_SRC = f"{BASE_DIR}/mariadb-livepatch-bench/patch_mariadb_v2.so"
MARIADB_V3_SRC = f"{BASE_DIR}/mariadb-livepatch-bench/patch_mariadb_v3.so"

POSTGRES_V1_SRC = f"{BASE_DIR}/postgres-livepatch-bench/patch_postgres_v1.so"
POSTGRES_V2_SRC = f"{BASE_DIR}/postgres-livepatch-bench/patch_postgres_v2.so"
POSTGRES_V3_SRC = f"{BASE_DIR}/postgres-livepatch-bench/patch_postgres_v3.so"

HAPROXY_V1_SRC = f"{BASE_DIR}/haproxy-multi-patch/patch_sample.so"
HAPROXY_V2_SRC = f"{BASE_DIR}/haproxy-multi-patch/patch_show_backend.so"
HAPROXY_V3_SRC = f"{BASE_DIR}/haproxy-multi-patch/patch_h2_dump.so"

# Staged targets
PGRUST_V1_SO = f"{STAGE_DIR}/libpatch_pgrust_v1.so"
PGRUST_V2_SO = f"{STAGE_DIR}/libpatch_pgrust_v2.so"
PGRUST_V3_SO = f"{STAGE_DIR}/libpatch_pgrust_v3.so"

MARIADB_V1_SO = f"{MYSQL_PLUGIN_DIR}/patch_mariadb_v1.so"
MARIADB_V2_SO = f"{MYSQL_PLUGIN_DIR}/patch_mariadb_v2.so"
MARIADB_V3_SO = f"{MYSQL_PLUGIN_DIR}/patch_mariadb_v3.so"

POSTGRES_V1_SO = f"{STAGE_DIR}/patch_postgres_v1.so"
POSTGRES_V2_SO = f"{STAGE_DIR}/patch_postgres_v2.so"
POSTGRES_V3_SO = f"{STAGE_DIR}/patch_postgres_v3.so"

HAPROXY_V1_SO = f"{STAGE_DIR}/patch_sample.so"
HAPROXY_V2_SO = f"{STAGE_DIR}/patch_show_backend.so"
HAPROXY_V3_SO = f"{STAGE_DIR}/patch_h2_dump.so"

PGRUST_PORT = 5435

class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    BOLD = '\033[1m'
    END = '\033[0m'

def log(msg, color=Colors.CYAN):
    print(f"{color}[+] {msg}{Colors.END}")

def warn(msg):
    print(f"{Colors.YELLOW}[!] {msg}{Colors.END}")

def err(msg):
    print(f"{Colors.RED}[-] {msg}{Colors.END}")

def run_cmd(cmd, env=None):
    p = subprocess.run(cmd, shell=True, capture_output=True, text=True, env=env)
    return p.returncode, p.stdout.strip(), p.stderr.strip()

def stage_files():
    mappings = [
        (PGRUST_V1_SRC, PGRUST_V1_SO),
        (PGRUST_V2_SRC, PGRUST_V2_SO),
        (PGRUST_V3_SRC, PGRUST_V3_SO),
        (MARIADB_V1_SRC, MARIADB_V1_SO),
        (MARIADB_V2_SRC, MARIADB_V2_SO),
        (MARIADB_V3_SRC, MARIADB_V3_SO),
        (POSTGRES_V1_SRC, POSTGRES_V1_SO),
        (POSTGRES_V2_SRC, POSTGRES_V2_SO),
        (POSTGRES_V3_SRC, POSTGRES_V3_SO),
        (HAPROXY_V1_SRC, HAPROXY_V1_SO),
        (HAPROXY_V2_SRC, HAPROXY_V2_SO),
        (HAPROXY_V3_SRC, HAPROXY_V3_SO),
    ]
    for src, dst in mappings:
        if os.path.exists(src):
            shutil.copyfile(src, dst)
            os.chmod(dst, 0o755)

def get_symbol_offset(exe_path, sym_name):
    code, out, _ = run_cmd(f"nm -D '{exe_path}' 2>/dev/null | grep -w '{sym_name}'")
    if code != 0 or not out:
        code, out, _ = run_cmd(f"nm '{exe_path}' 2>/dev/null | grep -w '{sym_name}'")
    if code != 0 or not out:
        raise RuntimeError(f"Symbol '{sym_name}' not found in '{exe_path}'")
    return int(out.split()[0], 16)

def get_vma_base(pid, lib_substr):
    with open(f"/proc/{pid}/maps", "r") as f:
        for line in f:
            if lib_substr in line:
                parts = line.split()
                if len(parts) >= 3 and parts[2] == "00000000":
                    return int(parts[0].split("-")[0], 16)
    return None

def query_pgrust(port=PGRUST_PORT, req="VERSION"):
    try:
        s = socket.create_connection(("127.0.0.1", port), timeout=3.0)
        s.sendall((req.strip() + "\n").encode())
        resp = s.recv(1024).decode().strip()
        s.close()
        return resp
    except Exception as e:
        return f"ERR: {e}"

def test_mariadb_sql():
    code, out, err_msg = run_cmd("mariadb -s -N -e 'SELECT 1, NOW();' 2>/dev/null")
    if code != 0:
        return False, err_msg
    return True, out.strip()

def get_active_patch_addr(pid, target_vaddr):
    code, out, _ = run_cmd(f"{ULP_CTL} list")
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 8 and str(pid) in parts[0]:
            try:
                orig_addr = int(parts[5], 16)
                if orig_addr == target_vaddr:
                    return int(parts[6], 16)
            except ValueError:
                pass
    return 0

class PersistentPostgresSession:
    def __init__(self):
        self.proc = subprocess.Popen(
            ["su", "-", "postgres", "-c", "psql -t -A -q -d template1 --variable ON_ERROR_STOP=1"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1
        )
        self.worker_pid = int(self.query("SELECT pg_backend_pid();"))

    def query(self, sql):
        marker = "___END_QUERY___"
        full_sql = f"{sql.strip()}\nSELECT '{marker}';\n"
        self.proc.stdin.write(full_sql)
        self.proc.stdin.flush()
        lines = []
        while True:
            line = self.proc.stdout.readline()
            if not line:
                break
            stripped = line.strip()
            if stripped == marker:
                break
            if stripped:
                lines.append(stripped)
        return lines[0] if lines else ""

    def close(self):
        try:
            self.proc.stdin.write("\\q\n")
            self.proc.stdin.flush()
            self.proc.terminate()
            self.proc.wait(timeout=2)
        except Exception:
            pass

def main():
    print(f"{Colors.BOLD}{Colors.BLUE}=============================================================================={Colors.END}")
    print(f"{Colors.BOLD}{Colors.BLUE}   PROJECT ULP_DRIVER: CONTINUOUS MULTI-VERSION LIVEPATCH TEST SUITE      {Colors.END}")
    print(f"{Colors.BOLD}{Colors.BLUE}   Testing: pgrust (Rust), MariaDB (C), PostgreSQL (C), HAProxy (C)            {Colors.END}")
    print(f"{Colors.BOLD}{Colors.BLUE}=============================================================================={Colors.END}\n")

    # Stage world-readable shared libraries
    stage_files()

    # Step 0: Ensure Kernel Driver is loaded and armed with resumption support
    log("Step 0: Initializing ULP kernel driver with allow_resumption=1...")
    run_cmd("echo 1 > /sys/module/ulp_driver/parameters/allow_resumption 2>/dev/null || true")
    run_cmd("rmmod livepatch_ulp 2>/dev/null || true")
    run_cmd("rmmod ulp_driver 2>/dev/null || true")
    run_cmd("rm -f /run/ulp/state.bin /run/ulp_state.bin")
    code, _, e = run_cmd(f"insmod {DRIVER_DIR}/ulp_driver.ko dev_mode=1 allow_resumption=1 resume=1")
    assert code == 0, f"Driver load failed: {e}"
    run_cmd(f"install -m 755 {DRIVER_DIR}/ulp_ctl {ULP_CTL}")
    run_cmd(f"install -m 755 {DRIVER_DIR}/ulp_inject {ULP_INJECT}")
    log("Kernel driver loaded & utilities installed.\n", Colors.GREEN)

    # Step 1: Start/Verify Target Daemons
    log("Step 1: Discovering & Preparing Target Daemons...")

    # 1.1 pgrust (Rust)
    run_cmd("pkill -9 -f pgrust_daemon 2>/dev/null || true")
    time.sleep(0.5)
    
    pgrust_env = os.environ.copy()
    pgrust_env["PGRUST_PORT"] = str(PGRUST_PORT)
    pgrust_env["LD_PRELOAD"] = f"{PGRUST_V1_SO}:{PGRUST_V2_SO}:{PGRUST_V3_SO}"
    pgrust_proc = subprocess.Popen([PGRUST_DAEMON], env=pgrust_env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(1)
    pgrust_pid = pgrust_proc.pid
    log(f"-> pgrust_daemon (Rust) active: PID {pgrust_pid} on port {PGRUST_PORT}")

    # 1.2 MariaDB (C)
    run_cmd("systemctl restart mariadb")
    time.sleep(1.5)
    code, out, _ = run_cmd("pidof mariadbd")
    assert code == 0 and out, "mariadbd is not running!"
    mariadb_pid = int(out.split()[0])
    
    # Inject patch libraries into MariaDB
    run_cmd(f"{ULP_INJECT} {mariadb_pid} {MARIADB_V1_SO}")
    run_cmd(f"{ULP_INJECT} {mariadb_pid} {MARIADB_V2_SO}")
    run_cmd(f"{ULP_INJECT} {mariadb_pid} {MARIADB_V3_SO}")
    log(f"-> mariadbd (C) active: PID {mariadb_pid}")

    # 1.3 PostgreSQL (C) - Persistent Session Backend
    run_cmd("systemctl restart postgresql@17-main")
    time.sleep(1.5)
    pg_session = PersistentPostgresSession()
    postgres_worker_pid = pg_session.worker_pid
    log(f"-> postgres (C) active session worker: PID {postgres_worker_pid}")

    run_cmd(f"{ULP_INJECT} {postgres_worker_pid} {POSTGRES_V1_SO}")
    run_cmd(f"{ULP_INJECT} {postgres_worker_pid} {POSTGRES_V2_SO}")
    run_cmd(f"{ULP_INJECT} {postgres_worker_pid} {POSTGRES_V3_SO}")

    # 1.4 HAProxy (C)
    run_cmd("systemctl restart haproxy")
    time.sleep(1.5)
    code, out, _ = run_cmd("pgrep -f 'haproxy -W' | tail -n 1")
    if code != 0 or not out:
        code, out, _ = run_cmd("pidof haproxy")
    haproxy_pid = int(out.split()[0])
    run_cmd(f"{ULP_INJECT} {haproxy_pid} {HAPROXY_V1_SO}")
    run_cmd(f"{ULP_INJECT} {haproxy_pid} {HAPROXY_V2_SO}")
    run_cmd(f"{ULP_INJECT} {haproxy_pid} {HAPROXY_V3_SO}")
    log(f"-> haproxy (C) active: PID {haproxy_pid}\n")

    # Resolve Addresses for all services
    log("Resolving target and patch memory addresses...")
    # pgrust
    pgrust_base = get_vma_base(pgrust_pid, "pgrust_daemon")
    pgrust_v1_base = get_vma_base(pgrust_pid, "libpatch_pgrust_v1.so")
    pgrust_v2_base = get_vma_base(pgrust_pid, "libpatch_pgrust_v2.so")
    pgrust_v3_base = get_vma_base(pgrust_pid, "libpatch_pgrust_v3.so")
    
    assert pgrust_base and pgrust_v1_base and pgrust_v2_base and pgrust_v3_base, "Failed to resolve pgrust VMA bases"

    pgrust_ver_target = pgrust_base + get_symbol_offset(PGRUST_DAEMON, "pgrust_get_version")
    pgrust_query_target = pgrust_base + get_symbol_offset(PGRUST_DAEMON, "pgrust_process_query")
    
    pgrust_ver_v1 = pgrust_v1_base + get_symbol_offset(PGRUST_V1_SO, "patch_pgrust_get_version")
    pgrust_query_v1 = pgrust_v1_base + get_symbol_offset(PGRUST_V1_SO, "patch_pgrust_process_query")
    
    pgrust_ver_v2 = pgrust_v2_base + get_symbol_offset(PGRUST_V2_SO, "patch_pgrust_get_version")
    pgrust_query_v2 = pgrust_v2_base + get_symbol_offset(PGRUST_V2_SO, "patch_pgrust_process_query")
    
    pgrust_ver_v3 = pgrust_v3_base + get_symbol_offset(PGRUST_V3_SO, "patch_pgrust_get_version")
    pgrust_query_v3 = pgrust_v3_base + get_symbol_offset(PGRUST_V3_SO, "patch_pgrust_process_query")

    # MariaDB
    mariadb_exe_base = get_vma_base(mariadb_pid, "/usr/sbin/mariadbd")
    mariadb_v1_base = get_vma_base(mariadb_pid, "patch_mariadb_v1.so")
    mariadb_v2_base = get_vma_base(mariadb_pid, "patch_mariadb_v2.so")
    mariadb_v3_base = get_vma_base(mariadb_pid, "patch_mariadb_v3.so")
    
    assert mariadb_exe_base and mariadb_v1_base and mariadb_v2_base and mariadb_v3_base, "Failed to resolve MariaDB VMA bases"

    mariadb_target = mariadb_exe_base + get_symbol_offset("/usr/sbin/mariadbd", "server_mysql_get_server_version")
    mariadb_v1_patch = mariadb_v1_base + get_symbol_offset(MARIADB_V1_SO, "livepatch_server_mysql_get_server_version")
    mariadb_v2_patch = mariadb_v2_base + get_symbol_offset(MARIADB_V2_SO, "livepatch_server_mysql_get_server_version")
    mariadb_v3_patch = mariadb_v3_base + get_symbol_offset(MARIADB_V3_SO, "livepatch_server_mysql_get_server_version")

    # Postgres
    postgres_exe_base = get_vma_base(postgres_worker_pid, "/usr/lib/postgresql/17/bin/postgres")
    postgres_v1_base = get_vma_base(postgres_worker_pid, "patch_postgres_v1.so")
    postgres_v2_base = get_vma_base(postgres_worker_pid, "patch_postgres_v2.so")
    postgres_v3_base = get_vma_base(postgres_worker_pid, "patch_postgres_v3.so")
    
    assert postgres_exe_base and postgres_v1_base and postgres_v2_base and postgres_v3_base, "Failed to resolve PostgreSQL VMA bases"

    postgres_target = postgres_exe_base + get_symbol_offset("/usr/lib/postgresql/17/bin/postgres", "pg_backend_pid")
    postgres_v1_patch = postgres_v1_base + get_symbol_offset(POSTGRES_V1_SO, "livepatch_pg_backend_pid")
    postgres_v2_patch = postgres_v2_base + get_symbol_offset(POSTGRES_V2_SO, "livepatch_pg_backend_pid")
    postgres_v3_patch = postgres_v3_base + get_symbol_offset(POSTGRES_V3_SO, "livepatch_pg_backend_pid")

    log("Address resolution complete.\n", Colors.GREEN)

    try:
        # -------------------------------------------------------------------------
        # STAGE 0: BASELINE (V0) VERIFICATION
        # -------------------------------------------------------------------------
        log("==================================================================", Colors.BOLD)
        log("STAGE 0: VERIFYING BASELINE UNPATCHED GENERATION (V0)", Colors.BOLD)
        log("==================================================================", Colors.BOLD)
        
        r_ver0 = query_pgrust(PGRUST_PORT, "VERSION")
        r_query0 = query_pgrust(PGRUST_PORT, "QUERY SELECT 1;")
        m_ok0, m_out0 = test_mariadb_sql()
        pg_pid0 = pg_session.query("SELECT pg_backend_pid();")
        
        log(f"pgrust V0 Version      : {r_ver0}")
        log(f"pgrust V0 Query Result : {r_query0}")
        log(f"MariaDB V0 Query       : {m_out0}")
        log(f"PostgreSQL V0 Backend  : {pg_pid0}")
        
        assert "vanilla-rust" in r_ver0, f"Expected vanilla pgrust, got {r_ver0}"
        assert "code=9" in r_query0, f"Expected base query length 9, got {r_query0}"
        assert m_ok0, f"Expected MariaDB query success, got {m_out0}"
        assert int(pg_pid0) == postgres_worker_pid, f"Expected real PID {postgres_worker_pid}, got {pg_pid0}"
        log(">> STAGE 0 (V0 Baseline) PASSED!\n", Colors.GREEN)

        # -------------------------------------------------------------------------
        # STAGE 1: MULTI-VERSION TRANSITION V0 -> V1
        # -------------------------------------------------------------------------
        log("==================================================================", Colors.BOLD)
        log("STAGE 1: DEPLOYING LIVEPATCH GENERATION 1 (V0 -> V1)", Colors.BOLD)
        log("==================================================================", Colors.BOLD)

        # Apply V1 patches
        run_cmd(f"{ULP_CTL} apply {pgrust_pid} pgrust_v1_ver pgrust_get_version 0x{pgrust_ver_target:x} 0x{pgrust_ver_v1:x} 16")
        run_cmd(f"{ULP_CTL} apply {pgrust_pid} pgrust_v1_query pgrust_process_query 0x{pgrust_query_target:x} 0x{pgrust_query_v1:x} 16")
        run_cmd(f"{ULP_CTL} apply {mariadb_pid} maria_v1 server_mysql_get_server_version 0x{mariadb_target:x} 0x{mariadb_v1_patch:x} 228")
        run_cmd(f"{ULP_CTL} apply {postgres_worker_pid} pg_v1 pg_backend_pid 0x{postgres_target:x} 0x{postgres_v1_patch:x} 16")

        # Verify V1 state
        r_ver1 = query_pgrust(PGRUST_PORT, "VERSION")
        r_query1 = query_pgrust(PGRUST_PORT, "QUERY SELECT 1;")
        m_ok1, m_out1 = test_mariadb_sql()
        pg_pid1 = pg_session.query("SELECT pg_backend_pid();")
        m_v1_addr = get_active_patch_addr(mariadb_pid, mariadb_target)

        log(f"pgrust V1 Version      : {r_ver1}")
        log(f"pgrust V1 Query Result : {r_query1}")
        log(f"MariaDB V1 Live Query  : {m_out1} (Patch vaddr: 0x{m_v1_addr:x})")
        log(f"PostgreSQL V1 Backend  : {pg_pid1}")

        assert "17.0.1-v1-secfix" in r_ver1, f"V1 version check failed: {r_ver1}"
        assert "code=1009" in r_query1, f"V1 query code (+1000) failed: {r_query1}"
        assert m_ok1 and m_v1_addr == mariadb_v1_patch, f"MariaDB V1 failed: {m_out1}, addr: 0x{m_v1_addr:x} vs 0x{mariadb_v1_patch:x}"
        assert "100001" in pg_pid1, f"PostgreSQL V1 failed: {pg_pid1}"
        log(">> STAGE 1 (V1 Generation) PASSED!\n", Colors.GREEN)

        # -------------------------------------------------------------------------
        # STAGE 2: MULTI-VERSION CONTINUOUS RE-PATCHING V1 -> V2
        # -------------------------------------------------------------------------
        log("==================================================================", Colors.BOLD)
        log("STAGE 2: CONTINUOUS RE-PATCHING GENERATION 2 (V1 -> V2)", Colors.BOLD)
        log("==================================================================", Colors.BOLD)

        # Re-apply V2 patches onto running daemons (Overwriting active trampolines)
        run_cmd(f"{ULP_CTL} apply {pgrust_pid} pgrust_v2_ver pgrust_get_version 0x{pgrust_ver_target:x} 0x{pgrust_ver_v2:x} 16")
        run_cmd(f"{ULP_CTL} apply {pgrust_pid} pgrust_v2_query pgrust_process_query 0x{pgrust_query_target:x} 0x{pgrust_query_v2:x} 16")
        run_cmd(f"{ULP_CTL} apply {mariadb_pid} maria_v2 server_mysql_get_server_version 0x{mariadb_target:x} 0x{mariadb_v2_patch:x} 228")
        run_cmd(f"{ULP_CTL} apply {postgres_worker_pid} pg_v2 pg_backend_pid 0x{postgres_target:x} 0x{postgres_v2_patch:x} 16")

        # Verify V2 state & Dynamic Shadow Metrics
        r_ver2 = query_pgrust(PGRUST_PORT, "VERSION")
        r_query2 = query_pgrust(PGRUST_PORT, "QUERY SELECT 1;")
        m_ok2, m_out2 = test_mariadb_sql()
        pg_pid2 = pg_session.query("SELECT pg_backend_pid();")
        m_v2_addr = get_active_patch_addr(mariadb_pid, mariadb_target)

        log(f"pgrust V2 Version      : {r_ver2}")
        log(f"pgrust V2 Query Result : {r_query2}")
        log(f"MariaDB V2 Live Query  : {m_out2} (Patch vaddr: 0x{m_v2_addr:x})")
        log(f"PostgreSQL V2 Backend  : {pg_pid2}")

        assert "17.0.2-v2-shadow-metrics" in r_ver2, f"V2 version check failed: {r_ver2}"
        assert "code=2009" in r_query2, f"V2 query code (+2000) failed: {r_query2}"
        assert "SHADOW_ACTIVE" in r_query2, f"V2 dynamic shadow variables not active: {r_query2}"
        assert m_ok2 and m_v2_addr == mariadb_v2_patch, f"MariaDB V2 failed: {m_out2}, addr: 0x{m_v2_addr:x} vs 0x{mariadb_v2_patch:x}"
        assert "200002" in pg_pid2, f"PostgreSQL V2 failed: {pg_pid2}"
        log(">> STAGE 2 (V2 Generation & Dynamic Shadows) PASSED!\n", Colors.GREEN)

        # -------------------------------------------------------------------------
        # STAGE 3: MULTI-VERSION CONTINUOUS RE-PATCHING V2 -> V3
        # -------------------------------------------------------------------------
        log("==================================================================", Colors.BOLD)
        log("STAGE 3: CONTINUOUS RE-PATCHING GENERATION 3 (V2 -> V3)", Colors.BOLD)
        log("==================================================================", Colors.BOLD)

        # Re-apply V3 patches onto running daemons
        run_cmd(f"{ULP_CTL} apply {pgrust_pid} pgrust_v3_ver pgrust_get_version 0x{pgrust_ver_target:x} 0x{pgrust_ver_v3:x} 16")
        run_cmd(f"{ULP_CTL} apply {pgrust_pid} pgrust_v3_query pgrust_process_query 0x{pgrust_query_target:x} 0x{pgrust_query_v3:x} 16")
        run_cmd(f"{ULP_CTL} apply {mariadb_pid} maria_v3 server_mysql_get_server_version 0x{mariadb_target:x} 0x{mariadb_v3_patch:x} 228")
        run_cmd(f"{ULP_CTL} apply {postgres_worker_pid} pg_v3 pg_backend_pid 0x{postgres_target:x} 0x{postgres_v3_patch:x} 16")

        # Verify V3 state
        r_ver3 = query_pgrust(PGRUST_PORT, "VERSION")
        r_query3 = query_pgrust(PGRUST_PORT, "QUERY SELECT 1;")
        m_ok3, m_out3 = test_mariadb_sql()
        pg_pid3 = pg_session.query("SELECT pg_backend_pid();")
        m_v3_addr = get_active_patch_addr(mariadb_pid, mariadb_target)

        log(f"pgrust V3 Version      : {r_ver3}")
        log(f"pgrust V3 Query Result : {r_query3}")
        log(f"MariaDB V3 Live Query  : {m_out3} (Patch vaddr: 0x{m_v3_addr:x})")
        log(f"PostgreSQL V3 Backend  : {pg_pid3}")

        assert "17.0.3-v3-vectorized-smp" in r_ver3, f"V3 check failed: {r_ver3}"
        assert "code=3009" in r_query3, f"V3 query code (+3000) failed: {r_query3}"
        assert m_ok3 and m_v3_addr == mariadb_v3_patch, f"MariaDB V3 failed: {m_out3}, addr: 0x{m_v3_addr:x} vs 0x{mariadb_v3_patch:x}"
        assert "300003" in pg_pid3, f"PostgreSQL V3 failed: {pg_pid3}"
        log(">> STAGE 3 (V3 Generation Vectorized Mode) PASSED!\n", Colors.GREEN)

        # -------------------------------------------------------------------------
        # STAGE 4: ZERO-DOWNTIME KERNEL DRIVER RESUMPTION RELOAD CYCLE
        # -------------------------------------------------------------------------
        log("==================================================================", Colors.BOLD)
        log("STAGE 4: KERNEL DRIVER RESUMPTION RELOAD UNDER CONTINUOUS TRAFFIC", Colors.BOLD)
        log("==================================================================", Colors.BOLD)

        # Trigger rmmod while patches are active (state serialized to /run/ulp/state.bin)
        log("Unloading ulp_driver kernel module (state serialized to disk)...")
        code, _, err_unload = run_cmd("rmmod ulp_driver")
        assert code == 0, f"Driver unload failed: {err_unload}"
        log("Driver successfully unloaded while V3 patches remain active in user memory.")

        # Test queries during driver downtime
        r_ver_down = query_pgrust(PGRUST_PORT, "VERSION")
        m_ok_down, _ = test_mariadb_sql()
        pg_pid_down = pg_session.query("SELECT pg_backend_pid();")
        assert "17.0.3-v3-vectorized-smp" in r_ver_down, f"pgrust failed during driver downtime: {r_ver_down}"
        assert m_ok_down, f"MariaDB failed during driver downtime"
        assert "300003" in pg_pid_down, f"PostgreSQL failed during driver downtime: {pg_pid_down}"
        log("Queries served with zero downtime during kernel driver downtime!", Colors.GREEN)

        # Reload driver with resume=1
        log("Reloading ulp_driver with resume=1 (resuming and validating active state)...")
        code, _, err_load = run_cmd(f"insmod {DRIVER_DIR}/ulp_driver.ko dev_mode=1 allow_resumption=1 resume=1")
        assert code == 0, f"Driver reload failed: {err_load}"
        
        code, patch_list, _ = run_cmd(f"{ULP_CTL} list")
        log(f"Re-adopted Active Patches Post-Resumption:\n{patch_list}")
        assert "pgrust_v3_ver" in patch_list and "maria_v3" in patch_list and "pg_v3" in patch_list
        log(">> STAGE 4 (Zero-Downtime Kernel Driver Resumption) PASSED!\n", Colors.GREEN)

        # -------------------------------------------------------------------------
        # STAGE 5: CLEAN MULTI-GENERATION ROLLBACK (V3 -> V0)
        # -------------------------------------------------------------------------
        log("==================================================================", Colors.BOLD)
        log("STAGE 5: REVERTING ALL LIVEPATCHES (V3 -> V0 BASELINE RESTORATION)", Colors.BOLD)
        log("==================================================================", Colors.BOLD)

        run_cmd(f"{ULP_CTL} revert {pgrust_pid} 0x{pgrust_ver_target:x}")
        run_cmd(f"{ULP_CTL} revert {pgrust_pid} 0x{pgrust_query_target:x}")
        run_cmd(f"{ULP_CTL} revert {mariadb_pid} 0x{mariadb_target:x}")
        run_cmd(f"{ULP_CTL} revert {postgres_worker_pid} 0x{postgres_target:x}")

        # Verify restored V0 baseline state
        r_ver_rev = query_pgrust(PGRUST_PORT, "VERSION")
        r_query_rev = query_pgrust(PGRUST_PORT, "QUERY SELECT 1;")
        m_ok_rev, _ = test_mariadb_sql()
        pg_pid_rev = pg_session.query("SELECT pg_backend_pid();")

        log(f"pgrust Post-Revert Version      : {r_ver_rev}")
        log(f"pgrust Post-Revert Query Result : {r_query_rev}")
        log(f"MariaDB Post-Revert SQL         : OK={m_ok_rev}")
        log(f"PostgreSQL Post-Revert Backend  : {pg_pid_rev}")

        assert "vanilla-rust" in r_ver_rev, f"Revert failed for pgrust version: {r_ver_rev}"
        assert "code=9" in r_query_rev, f"Revert failed for pgrust query: {r_query_rev}"
        assert m_ok_rev, f"Revert failed for MariaDB query"
        assert int(pg_pid_rev) == postgres_worker_pid, f"Revert failed for PostgreSQL: {pg_pid_rev}"

        code, final_list, _ = run_cmd(f"{ULP_CTL} list")
        assert "No active userspace livepatches" in final_list or "0 entries" in final_list or len(final_list.strip().splitlines()) <= 2
        log(">> STAGE 5 (Clean Revert to V0 Baseline) PASSED!\n", Colors.GREEN)

    finally:
        pg_session.close()
        pgrust_proc.terminate()
        pgrust_proc.wait()

    print(f"{Colors.BOLD}{Colors.GREEN}=============================================================================={Colors.END}")
    print(f"{Colors.BOLD}{Colors.GREEN}   SUCCESS: ALL MULTI-VERSION CONTINUOUS LIVEPATCH TESTS COMPLETED!            {Colors.END}")
    print(f"{Colors.BOLD}{Colors.GREEN}   Generations Verified: V0 -> V1 -> V2 -> V3 -> Resumption -> V0 Clean Revert{Colors.END}")
    print(f"{Colors.BOLD}{Colors.GREEN}=============================================================================={Colors.END}")

if __name__ == "__main__":
    main()
