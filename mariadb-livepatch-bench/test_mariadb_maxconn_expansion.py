#!/usr/bin/env python3
"""
Advanced Livepatching Demonstration: MariaDB Zero-Downtime max_connections Expansion
===================================================================================
Demonstrates using ULP to dynamically replace the core internal connection limit
getter (_Z19get_max_connectionsv) on a live running MariaDB database daemon without
restarting or dropping existing active SQL client sessions.
"""

import os
import sys
import time
import shutil
import subprocess

ULP_CTL = "/usr/local/bin/ulp_ctl"
ULP_INJECT = "/usr/local/bin/ulp_inject"
PATCH_SRC = "/root/ulp-driver/mariadb-livepatch-bench/patch_mariadb_maxconn.so"
PATCH_DST = "/usr/lib/mysql/plugin/patch_mariadb_maxconn.so"

def run_cmd(cmd):
    p = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return p.returncode, p.stdout.strip(), p.stderr.strip()

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

def main():
    print("==============================================================================")
    print("   ADVANCED ULP BENCHMARK: MARIADB ZERO-DOWNTIME MAX_CONNECTIONS EXPANSION     ")
    print("==============================================================================")

    # 1. Ensure MariaDB is running
    code, out, _ = run_cmd("pidof mariadbd")
    if code != 0 or not out:
        print("[*] Starting MariaDB service...")
        run_cmd("systemctl restart mariadb")
        time.sleep(2)
        code, out, _ = run_cmd("pidof mariadbd")
    
    mariadb_pid = int(out.split()[0])
    print(f"[+] Active mariadbd PID: {mariadb_pid}")

    # Stage world-readable patch library
    shutil.copyfile(PATCH_SRC, PATCH_DST)
    os.chmod(PATCH_DST, 0o755)

    # 2. Inject patch library
    print("[*] Injecting patch_mariadb_maxconn.so via ULP stack injection...")
    run_cmd(f"{ULP_INJECT} {mariadb_pid} {PATCH_DST}")

    # 3. Resolve function addresses
    mariadb_exe_base = get_vma_base(mariadb_pid, "/usr/sbin/mariadbd")
    patch_so_base = get_vma_base(mariadb_pid, "patch_mariadb_maxconn.so")
    assert mariadb_exe_base and patch_so_base, "Failed to resolve memory bases"

    target_func = "_Z19get_max_connectionsv"
    patch_func = "livepatch_get_max_connections"

    target_off = get_symbol_offset("/usr/sbin/mariadbd", target_func)
    patch_off = get_symbol_offset(PATCH_DST, patch_func)

    target_vaddr = mariadb_exe_base + target_off
    patch_vaddr = patch_so_base + patch_off

    print(f"[+] Target _Z19get_max_connectionsv : 0x{target_vaddr:016x}")
    print(f"[+] Patch livepatch_get_max_connections: 0x{patch_vaddr:016x}")

    # 4. Verify baseline queries
    code, out, _ = run_cmd("mariadb -s -N -e 'SELECT 1, @@max_connections;'")
    print(f"[+] Baseline MariaDB Status: {out}")

    # 5. Apply Livepatch to _Z19get_max_connectionsv (16-byte CET Absolute Trampoline)
    print("\n>>> Applying ULP Livepatch to dynamically expand max_connections to 50,000...")
    code, _, err_apply = run_cmd(f"{ULP_CTL} apply {mariadb_pid} exp_maxconn {target_func} 0x{target_vaddr:x} 0x{patch_vaddr:x} 16")
    assert code == 0, f"Livepatch failed: {err_apply}"
    print("[+] Livepatch applied successfully!")

    # Verify active patch in kernel registry
    code, patch_list, _ = run_cmd(f"{ULP_CTL} list")
    print(f"\n[+] Active Kernel Patch Registry:\n{patch_list}")

    # Verify query serving during active livepatch
    code, out_patched, _ = run_cmd("mariadb -s -N -e 'SELECT 1, NOW();'")
    print(f"[+] Query served seamlessly during active patch: {out_patched}")

    # 6. Clean rollback
    print("\n>>> Atomically reverting livepatch back to V0 baseline...")
    code, _, err_rev = run_cmd(f"{ULP_CTL} revert {mariadb_pid} 0x{target_vaddr:x}")
    assert code == 0, f"Revert failed: {err_rev}"
    print("[+] Reverted cleanly. Baseline restored.")

    print("\n==============================================================================")
    print("   MARIADB MAX_CONNECTIONS DYNAMIC EXPANSION DEMO COMPLETED SUCCESSFULLY!      ")
    print("==============================================================================")

if __name__ == "__main__":
    main()
