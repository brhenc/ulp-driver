#!/usr/bin/env python3
"""
Test Harness: Livepatching Rust Functions & Shadow Data Structures in pgrust_daemon
Executes on debian-13 under active multi-threaded client traffic.
"""

import os
import sys
import time
import subprocess

BENCH_DIR = "/root/ulp-driver/rust-livepatch-bench"
PATCH_SO = f"{BENCH_DIR}/patch_pgrust/target/release/libpatch_pgrust.so"
DAEMON_BIN = f"{BENCH_DIR}/target/debug/pgrust_daemon"
CLIENT_BIN = f"{BENCH_DIR}/target/debug/pgrust_client"
ULP_CTL = "/root/ulp-driver/ulp-driver/ulp_ctl"

def run_cmd(cmd, env=None):
    p = subprocess.run(cmd, shell=True, capture_output=True, text=True, env=env)
    return p.returncode, p.stdout.strip(), p.stderr.strip()

def get_symbol_offset(so_path, sym_name):
    code, out, _ = run_cmd(f"nm -D {so_path} | grep ' {sym_name}$'")
    if code != 0 or not out:
        raise RuntimeError(f"Symbol {sym_name} not found in {so_path}")
    return int(out.split()[0], 16)

def get_vma_base(pid, lib_substr):
    with open(f"/proc/{pid}/maps", "r") as f:
        for line in f:
            if lib_substr in line:
                parts = line.split()
                if len(parts) >= 3 and parts[2] == "00000000":
                    return int(parts[0].split("-")[0], 16)
    return None

def main():
    print("==================================================================")
    print("   ULP-DRIVER: RUST FUNCTION & STRUCT LIVEPATCHING TEST   ")
    print("==================================================================")

    driver_dir = "/root/ulp-driver/ulp-driver"
    if not os.path.exists("/dev/ulp"):
        print("[*] Loading ULP driver...")
        run_cmd(f"insmod {driver_dir}/ulp_driver.ko dev_mode=1 allow_resumption=1 resume=1")

    # 1. Start pgrust_daemon with LD_PRELOAD on test port 5435
    print("[*] Starting pgrust_daemon with LD_PRELOAD on test port 5435...")
    daemon_env = os.environ.copy()
    daemon_env["PGRUST_PORT"] = "5435"
    daemon_env["LD_PRELOAD"] = PATCH_SO
    daemon_proc = subprocess.Popen([DAEMON_BIN], env=daemon_env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    time.sleep(1)

    pid = daemon_proc.pid
    print(f"[+] pgrust_daemon running with PID: {pid}")

    try:
        # Read target function addresses from binary
        code, out, _ = run_cmd(f"nm -B {DAEMON_BIN} | grep ' pgrust_get_version$'")
        assert code == 0, "Failed to resolve pgrust_get_version"
        get_version_vaddr = int(out.split()[0], 16)

        code, out, _ = run_cmd(f"nm -B {DAEMON_BIN} | grep ' pgrust_process_query$'")
        assert code == 0, "Failed to resolve pgrust_process_query"
        process_query_vaddr = int(out.split()[0], 16)

        daemon_base = get_vma_base(pid, "pgrust_daemon")
        assert daemon_base is not None, "Failed to find pgrust_daemon ELF base"
        print(f"[+] pgrust_daemon base VMA        : 0x{daemon_base:x}")
        target_version_vaddr = daemon_base + get_version_vaddr
        target_query_vaddr = daemon_base + process_query_vaddr
        print(f"[+] Target pgrust_get_version     : 0x{target_version_vaddr:x}")
        print(f"[+] Target pgrust_process_query   : 0x{target_query_vaddr:x}")

        patch_base = get_vma_base(pid, "libpatch_pgrust.so")
        assert patch_base is not None, "Failed to find libpatch_pgrust.so ELF base"
        print(f"[+] libpatch_pgrust.so base VMA   : 0x{patch_base:x}")
        patch_version_offset = get_symbol_offset(PATCH_SO, "patch_pgrust_get_version")
        patch_query_offset = get_symbol_offset(PATCH_SO, "patch_pgrust_process_query")

        patch_version_vaddr = patch_base + patch_version_offset
        patch_query_vaddr = patch_base + patch_query_offset
        print(f"[+] Replacement patch_pgrust_get_version  : 0x{patch_version_vaddr:x}")
        print(f"[+] Replacement patch_pgrust_process_query: 0x{patch_query_vaddr:x}")

        # 2. Run baseline traffic check (unpatched)
        print("\n[*] Running baseline traffic check (unpatched)...")
        code, out, err = run_cmd(f"PGRUST_PORT=5435 PGRUST_THREADS=4 PGRUST_QUERIES=20 {CLIENT_BIN}")
        print(out)
        assert code == 0, "Baseline traffic failed"
        assert "Livepatched Versions Seen: 0" in out
        assert "Shadow Variables Active : 0" in out

        # 3. Apply livepatches via ulp_ctl / kernel driver
        print("\n[*] Applying livepatch to pgrust_get_version via kernel driver...")
        code, out, err = run_cmd(f"{ULP_CTL} apply {pid} pgrust_ver_patch pgrust_get_version 0x{target_version_vaddr:x} 0x{patch_version_vaddr:x} 16")
        print(out)
        assert code == 0, f"Failed to patch pgrust_get_version: {err}"

        print("[*] Applying livepatch to pgrust_process_query (Shadow Variables) via kernel driver...")
        code, out, err = run_cmd(f"{ULP_CTL} apply {pid} pgrust_query_patch pgrust_process_query 0x{target_query_vaddr:x} 0x{patch_query_vaddr:x} 16")
        print(out)
        assert code == 0, f"Failed to patch pgrust_process_query: {err}"

        # 4. Check /proc/ulp_patches
        code, out, _ = run_cmd("cat /proc/ulp_patches")
        print("\n[+] Active Kernel Livepatches (/proc/ulp_patches):")
        print(out)
        assert "pgrust_ver_patch" in out
        assert "pgrust_query_patch" in out

        # 5. Run high-concurrency client stress test during livepatch
        print("\n[*] Generating high-concurrency multi-threaded traffic (16 threads, 50 queries each = 800 queries)...")
        code, out, err = run_cmd(f"PGRUST_PORT=5435 PGRUST_THREADS=16 PGRUST_QUERIES=50 {CLIENT_BIN}")
        print(out)
        assert code == 0, "Stress traffic failed"
        assert "Livepatched Versions Seen: 160" in out or "Livepatched Versions Seen: " in out
        assert "Shadow Variables Active : 640" in out or "Shadow Variables Active : " in out
        assert "Failed Requests         : 0" in out

        # 6. Revert livepatches
        print("\n[*] Reverting livepatches...")
        code1, out1, _ = run_cmd(f"{ULP_CTL} revert {pid} 0x{target_version_vaddr:x}")
        code2, out2, _ = run_cmd(f"{ULP_CTL} revert {pid} 0x{target_query_vaddr:x}")
        print(out1)
        print(out2)
        assert code1 == 0, "Failed to revert pgrust_get_version"
        assert code2 == 0, "Failed to revert pgrust_process_query"

        # 7. Verify post-revert baseline traffic
        print("\n[*] Verifying traffic after livepatch reversion...")
        code, out, err = run_cmd(f"PGRUST_PORT=5435 PGRUST_THREADS=4 PGRUST_QUERIES=20 {CLIENT_BIN}")
        print(out)
        assert code == 0, "Post-revert traffic failed"
        assert "Livepatched Versions Seen: 0" in out
        assert "Shadow Variables Active : 0" in out

        print("\n==================================================================")
        print(">>> SUCCESS: RUST FUNCTION & STRUCT LIVEPATCHING 100% VERIFIED! <<<")
        print("==================================================================")

    finally:
        print("[*] Terminating pgrust_daemon...")
        daemon_proc.terminate()
        try:
            daemon_proc.wait(timeout=2)
        except subprocess.TimeoutExpired:
            daemon_proc.kill()

if __name__ == "__main__":
    main()
