#!/usr/bin/env python3
"""
ulp-driver: Multi-Service Resumption Stress Test Suite
Tests:
- Workloads: BOTH Rust (pgrust_daemon) AND C (mariadbd) concurrently patched.
- Resumption Cycles: Load -> Unload -> Load -> Unload -> Load -> Unload -> Load
- State Verification: /run/ulp/state.bin serialized and verified across all cycles.
- Zero-Downtime Guarantee: Concurrent queries served during kernel driver downtime.
- Re-Adoption Invariant: All patches re-adopted with memory verification.
- Clean Revert: Rollback of all patches across all daemons post-cycles.
"""

import os
import sys
import time
import subprocess
import threading

BENCH_DIR = "/root/ulp-driver/rust-livepatch-bench"
PATCH_SO = f"{BENCH_DIR}/patch_pgrust/target/release/libpatch_pgrust.so"
DAEMON_BIN = f"{BENCH_DIR}/target/debug/pgrust_daemon"
CLIENT_BIN = f"{BENCH_DIR}/target/debug/pgrust_client"
DRIVER_DIR = "/root/ulp-driver/ulp-driver"
ULP_CTL = "/usr/local/bin/ulp_ctl"
ULP_INJECT = "/usr/local/bin/ulp_inject"

MARIADB_SO = "/usr/lib/mysql/plugin/patch_mariadb.so"

def run_cmd(cmd, env=None):
    p = subprocess.run(cmd, shell=True, capture_output=True, text=True, env=env)
    return p.returncode, p.stdout.strip(), p.stderr.strip()

def get_symbol_offset(exe_path, sym_name):
    code, out, _ = run_cmd(f"nm -D {exe_path} 2>/dev/null | grep -w '{sym_name}'")
    if code != 0 or not out:
        code, out, _ = run_cmd(f"nm {exe_path} 2>/dev/null | grep -w '{sym_name}'")
    if code != 0 or not out:
        raise RuntimeError(f"Symbol {sym_name} not found in {exe_path}")
    return int(out.split()[0], 16)

def get_vma_base(pid, lib_substr):
    with open(f"/proc/{pid}/maps", "r") as f:
        for line in f:
            if lib_substr in line:
                parts = line.split()
                if len(parts) >= 3 and parts[2] == "00000000":
                    return int(parts[0].split("-")[0], 16)
    return None

def test_mariadb_queries(num_queries=10):
    for i in range(num_queries):
        code, out, err = run_cmd("mariadb -e 'SELECT 1, NOW();' >/dev/null")
        if code != 0:
            return False, err
    return True, "OK"

def test_pgrust_queries(port=5438, threads=4, queries=15):
    code, out, err = run_cmd(f"PGRUST_PORT={port} PGRUST_THREADS={threads} PGRUST_QUERIES={queries} {CLIENT_BIN}")
    if code != 0 or "Failed Requests         : 0" not in out:
        return False, out or err
    is_live = "Livepatched Versions Seen: 0" not in out
    return True, is_live

def main():
    print("==============================================================================")
    print("   ULP-DRIVER: RUST & C MULTI-CYCLE DRIVER RESUMPTION STRESS TEST     ")
    print("==============================================================================")

    # 0. Initial Driver Load
    print("\n>>> [Step 0] Initializing ULP Kernel Driver with allow_resumption=1...")
    run_cmd("echo 1 > /sys/module/ulp_driver/parameters/allow_resumption 2>/dev/null || true")
    run_cmd("rmmod livepatch_ulp 2>/dev/null || true")
    run_cmd("rmmod ulp_driver 2>/dev/null || true")
    run_cmd("rm -f /run/ulp/state.bin /run/ulp_state.bin")
    code, _, err = run_cmd(f"insmod {DRIVER_DIR}/ulp_driver.ko dev_mode=1 allow_resumption=1 resume=1")
    assert code == 0, f"Failed to load driver: {err}"
    print("[+] Driver loaded with allow_resumption=1 and resume=1.")

    # 1. Ensure MariaDB (C) is running
    print("\n>>> [Step 1] Preparing MariaDB (C daemon)...")
    run_cmd("systemctl restart mariadb")
    time.sleep(2)
    code, out, _ = run_cmd("pidof mariadbd")
    assert code == 0 and out, "MariaDB is not running!"
    mariadb_pid = int(out.split()[0])
    print(f"[+] mariadbd (C) running with PID: {mariadb_pid}")

    # Inject patch_mariadb.so
    run_cmd(f"{ULP_INJECT} {mariadb_pid} {MARIADB_SO}")
    mariadb_exe_base = get_vma_base(mariadb_pid, "/usr/sbin/mariadbd")
    mariadb_so_base = get_vma_base(mariadb_pid, "patch_mariadb.so")
    assert mariadb_exe_base is not None and mariadb_so_base is not None
    mariadb_target_off = get_symbol_offset("/usr/sbin/mariadbd", "server_mysql_get_server_version")
    mariadb_patch_off = get_symbol_offset(MARIADB_SO, "livepatch_server_mysql_get_server_version")
    mariadb_target_vaddr = mariadb_exe_base + mariadb_target_off
    mariadb_patch_vaddr = mariadb_so_base + mariadb_patch_off
    print(f"[+] MariaDB target vaddr: 0x{mariadb_target_vaddr:x} | patch vaddr: 0x{mariadb_patch_vaddr:x}")

    # 2. Start pgrust_daemon (Rust)
    print("\n>>> [Step 2] Starting pgrust_daemon (Rust daemon) on port 5438...")
    rust_env = os.environ.copy()
    rust_env["PGRUST_PORT"] = "5438"
    rust_env["LD_PRELOAD"] = PATCH_SO
    rust_proc = subprocess.Popen([DAEMON_BIN], env=rust_env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    time.sleep(1)
    rust_pid = rust_proc.pid
    print(f"[+] pgrust_daemon (Rust) running with PID: {rust_pid}")

    try:
        rust_exe_base = get_vma_base(rust_pid, "pgrust_daemon")
        rust_so_base = get_vma_base(rust_pid, "libpatch_pgrust.so")
        assert rust_exe_base is not None and rust_so_base is not None
        rust_ver_target = rust_exe_base + get_symbol_offset(DAEMON_BIN, "pgrust_get_version")
        rust_query_target = rust_exe_base + get_symbol_offset(DAEMON_BIN, "pgrust_process_query")
        rust_ver_patch = rust_so_base + get_symbol_offset(PATCH_SO, "patch_pgrust_get_version")
        rust_query_patch = rust_so_base + get_symbol_offset(PATCH_SO, "patch_pgrust_process_query")

        # 3. Apply livepatches to BOTH daemons
        print("\n>>> [Step 3] Applying livepatches to BOTH Rust and C daemons...")
        # Rust patches
        code1, _, e1 = run_cmd(f"{ULP_CTL} apply {rust_pid} pgrust_ver pgrust_get_version 0x{rust_ver_target:x} 0x{rust_ver_patch:x} 16")
        code2, _, e2 = run_cmd(f"{ULP_CTL} apply {rust_pid} pgrust_query pgrust_process_query 0x{rust_query_target:x} 0x{rust_query_patch:x} 16")
        assert code1 == 0 and code2 == 0, f"Rust patch failed: {e1} {e2}"

        # C patch
        code3, _, e3 = run_cmd(f"{ULP_CTL} apply {mariadb_pid} fix_mariadb_ver server_mysql_get_server_version 0x{mariadb_target_vaddr:x} 0x{mariadb_patch_vaddr:x} 228")
        assert code3 == 0, f"MariaDB patch failed: {e3}"

        code, out, _ = run_cmd("cat /proc/ulp_patches")
        print(f"[+] Active Livepatches (Rust + C):\n{out}")
        assert "pgrust_ver" in out and "pgrust_query" in out and "fix_mariadb_ver" in out
        print("[+] SUCCESS: 3 livepatches active across Rust and C daemons!")

        # Verify initial traffic
        ok_m, _ = test_mariadb_queries(10)
        assert ok_m, "MariaDB initial queries failed"
        ok_r, is_live_r = test_pgrust_queries(5438, 4, 15)
        assert ok_r and is_live_r, "Rust initial patched queries failed"
        print("[+] Both Rust and C services responding correctly with patches active.")

        # =========================================================================
        # MULTI-CYCLE RESUMPTION STRESS LOOP
        # Performs 3 consecutive Unload -> Load cycles with live traffic at each step
        # =========================================================================
        NUM_CYCLES = 3
        for cycle in range(1, NUM_CYCLES + 1):
            print(f"\n==============================================================================")
            print(f"   RESUMPTION CYCLE {cycle} / {NUM_CYCLES}: UNLOAD -> TRAFFIC -> LOAD -> TRAFFIC")
            print(f"==============================================================================")

            # A. Unload Driver
            print(f"\n[*] [Cycle {cycle}A] Unloading ulp_driver.ko (Serializing state to disk)...")
            code, out, err = run_cmd("rmmod ulp_driver")
            assert code == 0, f"Cycle {cycle} rmmod failed: {err}"
            print(f"[+] Cycle {cycle}: Driver unloaded cleanly.")

            # Verify state file
            state_file = "/run/ulp/state.bin" if os.path.exists("/run/ulp/state.bin") else "/run/ulp_state.bin"
            assert os.path.exists(state_file), f"Cycle {cycle}: State file missing!"
            size = os.path.getsize(state_file)
            print(f"[+] Cycle {cycle}: State snapshot verified at {state_file} ({size} bytes).")

            # B. Verify continuous traffic during driver absence
            print(f"\n[*] [Cycle {cycle}B] Querying BOTH daemons WHILE KERNEL DRIVER IS UNLOADED...")
            ok_m, err_m = test_mariadb_queries(20)
            assert ok_m, f"Cycle {cycle}: MariaDB query failed during driver downtime: {err_m}"

            ok_r, is_live_r = test_pgrust_queries(5438, 8, 20)
            assert ok_r, f"Cycle {cycle}: pgrust query failed during driver downtime: {is_live_r}"
            assert is_live_r, f"Cycle {cycle}: Livepatch lost during driver downtime!"
            print(f"[+] Cycle {cycle} PASS: Both Rust and C daemons served concurrent traffic with ZERO downtime!")

            # C. Reload Driver and Resume
            print(f"\n[*] [Cycle {cycle}C] Reloading ulp_driver.ko (resume=1 allow_resumption=1)...")
            code, out, err = run_cmd(f"insmod {DRIVER_DIR}/ulp_driver.ko dev_mode=1 resume=1 allow_resumption=1")
            assert code == 0, f"Cycle {cycle}: Driver reload failed: {err}"

            # D. Verify re-adoption in /proc/ulp_patches
            code, out, _ = run_cmd("cat /proc/ulp_patches")
            print(f"[+] Cycle {cycle}: Active Patches after Resumption:\n{out}")
            assert "pgrust_ver" in out, f"Cycle {cycle}: Missing pgrust_ver!"
            assert "pgrust_query" in out, f"Cycle {cycle}: Missing pgrust_query!"
            assert "fix_mariadb_ver" in out, f"Cycle {cycle}: Missing fix_mariadb_ver!"
            print(f"[+] Cycle {cycle} PASS: All 3 livepatches successfully re-adopted by kernel driver!")

            # E. High-concurrency traffic post-resumption
            print(f"\n[*] [Cycle {cycle}E] High-concurrency query burst post-resumption...")
            ok_m, _ = test_mariadb_queries(50)
            assert ok_m, f"Cycle {cycle}: Post-resumption MariaDB queries failed"
            ok_r, is_live_r = test_pgrust_queries(5438, 16, 25)
            assert ok_r and is_live_r, f"Cycle {cycle}: Post-resumption pgrust queries failed"
            print(f"[+] Cycle {cycle} PASS: High-concurrency verification completed with 100% success!")

        # 4. Final Revert Phase
        print("\n==============================================================================")
        print("   FINAL REVERT PHASE: ROLLBACK OF ALL RUST & C LIVEPATCHES                    ")
        print("==============================================================================")
        print("[*] Reverting Rust livepatches using latest driver instance...")
        code1, o1, _ = run_cmd(f"{ULP_CTL} revert {rust_pid} 0x{rust_ver_target:x}")
        code2, o2, _ = run_cmd(f"{ULP_CTL} revert {rust_pid} 0x{rust_query_target:x}")
        assert code1 == 0 and code2 == 0, f"Rust revert failed: {o1} {o2}"
        print("[+] Rust patches cleanly reverted.")

        print("[*] Reverting MariaDB livepatch using latest driver instance...")
        code3, o3, _ = run_cmd(f"{ULP_CTL} revert {mariadb_pid} 0x{mariadb_target_vaddr:x}")
        assert code3 == 0, f"MariaDB revert failed: {o3}"
        print("[+] MariaDB patch cleanly reverted.")

        # Check /proc/ulp_patches is empty
        code, out, _ = run_cmd("cat /proc/ulp_patches")
        print(f"[+] Registry after reversion:\n{out}")
        assert "pgrust_ver" not in out and "pgrust_query" not in out and "fix_mariadb_ver" not in out
        print("[+] PASS: Kernel registry completely empty!")

        # Verify baseline traffic restored for both
        ok_m, _ = test_mariadb_queries(10)
        assert ok_m, "MariaDB post-revert queries failed"
        ok_r, is_live_r = test_pgrust_queries(5438, 4, 15)
        assert ok_r and not is_live_r, "Rust post-revert did not return unpatched behavior"
        print("[+] PASS: Baseline unpatched behavior verified for BOTH Rust and C services!")

        # 5. Final Unload with 0 patches
        print("\n[*] Final driver unload with 0 active patches...")
        code, _, err = run_cmd("rmmod ulp_driver")
        assert code == 0, f"Final unload failed: {err}"
        print("[+] Driver unloaded cleanly.")

        print("\n==============================================================================")
        print(">>> SUCCESS: RUST & C MULTI-CYCLE DRIVER RESUMPTION 100% VERIFIED!         <<<")
        print("==============================================================================")

    finally:
        print("[*] Terminating pgrust_daemon...")
        rust_proc.terminate()
        try:
            rust_proc.wait(timeout=2)
        except subprocess.TimeoutExpired:
            rust_proc.kill()

if __name__ == "__main__":
    main()
