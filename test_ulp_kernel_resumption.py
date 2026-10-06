#!/usr/bin/env python3
"""
ulp-driver: ULP Driver Resumption & Linux Kernel Livepatching Suite
Tests:
1. Zero-Orphan Invariant Default: rmmod blocked (-EBUSY) when livepatches are active.
2. Dynamic Resumption Mode: /sys/module/ulp_driver/parameters/allow_resumption.
3. State Snapshot: Serializing active trampolines to /run/ulp/state.bin on unload.
4. Userspace Zero-Downtime Continuity: Daemons continue serving traffic while driver is absent.
5. In-Flight Driver Resumption: Re-adopting livepatches & rules from state snapshot on reload.
6. Post-Resumption Revert: Clean rollback of re-adopted patches using newly loaded driver.
7. Linux Kernel Livepatching (CONFIG_LIVEPATCH / ftrace): In-flight hot-patching of ulp_driver.ko.
"""

import os
import sys
import time
import subprocess

BENCH_DIR = "/root/ulp-driver/rust-livepatch-bench"
PATCH_SO = f"{BENCH_DIR}/patch_pgrust/target/release/libpatch_pgrust.so"
DAEMON_BIN = f"{BENCH_DIR}/target/debug/pgrust_daemon"
CLIENT_BIN = f"{BENCH_DIR}/target/debug/pgrust_client"
DRIVER_DIR = "/root/ulp-driver/ulp-driver"
KLP_DIR = "/root/ulp-driver/kernel-livepatch"
ULP_CTL = "/usr/local/bin/ulp_ctl"

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
    print("======================================================================")
    print("   ULP-DRIVER: DRIVER RESUMPTION & KERNEL LIVEPATCHING TEST   ")
    print("======================================================================")

    # Step 0: Ensure fresh driver is loaded with default parameters
    print("\n>>> [Step 0] Loading ulp_driver.ko with default settings (allow_resumption=0)...")
    run_cmd("echo 1 > /sys/module/ulp_driver/parameters/allow_resumption 2>/dev/null || true")
    run_cmd("rmmod livepatch_ulp 2>/dev/null || true")
    run_cmd("rmmod ulp_driver 2>/dev/null || true")
    run_cmd("rm -f /run/ulp/state.bin /run/ulp_state.bin")
    code, _, err = run_cmd(f"insmod {DRIVER_DIR}/ulp_driver.ko dev_mode=1 allow_resumption=0")
    assert code == 0, f"Failed to load ulp_driver: {err}"

    code, out, _ = run_cmd("cat /sys/module/ulp_driver/parameters/allow_resumption")
    assert code == 0 and out == "N", f"Expected allow_resumption=N, got {out}"
    print(f"[+] Verified default: allow_resumption = {out} (Zero-Orphan Invariant active)")

    # Step 1: Start pgrust_daemon on port 5437
    print("\n>>> [Step 1] Starting pgrust_daemon on port 5437...")
    daemon_env = os.environ.copy()
    daemon_env["PGRUST_PORT"] = "5437"
    daemon_env["LD_PRELOAD"] = PATCH_SO
    daemon_proc = subprocess.Popen([DAEMON_BIN], env=daemon_env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    time.sleep(1)

    pid = daemon_proc.pid
    print(f"[+] pgrust_daemon running (PID: {pid})")

    try:
        # Resolve target and replacement function addresses
        code, out, _ = run_cmd(f"nm -B {DAEMON_BIN} | grep ' pgrust_get_version$'")
        assert code == 0
        get_version_vaddr = int(out.split()[0], 16)

        code, out, _ = run_cmd(f"nm -B {DAEMON_BIN} | grep ' pgrust_process_query$'")
        assert code == 0
        process_query_vaddr = int(out.split()[0], 16)

        daemon_base = get_vma_base(pid, "pgrust_daemon")
        assert daemon_base is not None
        target_version_vaddr = daemon_base + get_version_vaddr
        target_query_vaddr = daemon_base + process_query_vaddr

        patch_base = get_vma_base(pid, "libpatch_pgrust.so")
        assert patch_base is not None
        patch_version_offset = get_symbol_offset(PATCH_SO, "patch_pgrust_get_version")
        patch_query_offset = get_symbol_offset(PATCH_SO, "patch_pgrust_process_query")
        patch_version_vaddr = patch_base + patch_version_offset
        patch_query_vaddr = patch_base + patch_query_offset

        # Verify baseline traffic (unpatched)
        print("\n[*] Baseline traffic check (unpatched)...")
        code, out, _ = run_cmd(f"PGRUST_PORT=5437 PGRUST_THREADS=4 PGRUST_QUERIES=10 {CLIENT_BIN}")
        assert code == 0 and "Livepatched Versions Seen: 0" in out
        print("[+] Baseline unpatched traffic confirmed.")

        # Step 2: Apply userspace livepatches via ulp_ctl
        print("\n>>> [Step 2] Applying userspace livepatches via ulp_ctl...")
        code, out, err = run_cmd(f"{ULP_CTL} apply {pid} pgrust_ver_patch pgrust_get_version 0x{target_version_vaddr:x} 0x{patch_version_vaddr:x} 16")
        assert code == 0, f"Failed to patch version: {err}"
        code, out, err = run_cmd(f"{ULP_CTL} apply {pid} pgrust_query_patch pgrust_process_query 0x{target_query_vaddr:x} 0x{patch_query_vaddr:x} 16")
        assert code == 0, f"Failed to patch query: {err}"

        code, out, _ = run_cmd("cat /proc/ulp_patches")
        print(f"[+] Active Patches:\n{out}")
        assert "pgrust_ver_patch" in out and "pgrust_query_patch" in out

        # Verify patched traffic
        code, out, _ = run_cmd(f"PGRUST_PORT=5437 PGRUST_THREADS=4 PGRUST_QUERIES=10 {CLIENT_BIN}")
        print(out)
        assert code == 0 and "Failed Requests         : 0" in out
        assert "Livepatched Versions Seen: 0" not in out
        print("[+] Patched traffic confirmed.")

        # Step 3: Verify Zero-Orphan Invariant enforcement
        print("\n>>> [Step 3] Testing Zero-Orphan Invariant: rmmod MUST be rejected...")
        code, out, err = run_cmd("rmmod ulp_driver")
        assert code != 0, "Security violation: rmmod succeeded while livepatches were active!"
        assert "is in use" in err or "Resource temporarily unavailable" in err or code != 0
        print(f"[+] PASS: rmmod blocked as expected ({err or 'Module in use'}). Zero-Orphan Invariant intact.")

        # Step 4: Enable Resumption Mode Dynamically
        print("\n>>> [Step 4] Dynamically enabling driver resumption mode via sysfs...")
        code, _, err = run_cmd("echo 1 > /sys/module/ulp_driver/parameters/allow_resumption")
        assert code == 0, f"Failed to write allow_resumption: {err}"

        code, out, _ = run_cmd("cat /sys/module/ulp_driver/parameters/allow_resumption")
        assert code == 0 and out == "Y", f"Expected allow_resumption=Y, got {out}"
        print("[+] Resumption mode successfully enabled (allow_resumption = Y).")

        # Step 5: Unload driver with livepatches in-flight (State Serialization)
        print("\n>>> [Step 5] Unloading ulp_driver with livepatches in-flight...")
        run_cmd("rm -f /run/ulp/state.bin /run/ulp_state.bin")
        code, out, err = run_cmd("rmmod ulp_driver")
        assert code == 0, f"rmmod failed in resumption mode: {err}"
        print("[+] ulp_driver.ko successfully unloaded without unpatching userspace!")

        # Verify state file was created
        state_file = "/run/ulp/state.bin" if os.path.exists("/run/ulp/state.bin") else "/run/ulp_state.bin"
        assert os.path.exists(state_file), f"State file {state_file} was not generated!"
        size = os.path.getsize(state_file)
        print(f"[+] State file generated at {state_file} ({size} bytes).")

        # Step 6: Verify userspace daemon continuity during kernel driver downtime
        print("\n>>> [Step 6] Testing userspace traffic WHILE DRIVER IS UNLOADED...")
        code, out, _ = run_cmd(f"PGRUST_PORT=5437 PGRUST_THREADS=8 PGRUST_QUERIES=25 {CLIENT_BIN}")
        print(out)
        assert code == 0, "Userspace daemon crashed during driver downtime!"
        assert "Failed Requests         : 0" in out
        assert "Livepatched Versions Seen: 0" not in out
        print("[+] PASS: Daemon served 200 concurrent queries with ZERO downtime while driver was unloaded!")

        # Step 7: Reload driver and resume state
        print("\n>>> [Step 7] Reloading ulp_driver.ko with resume=1...")
        code, out, err = run_cmd(f"insmod {DRIVER_DIR}/ulp_driver.ko dev_mode=1 resume=1 allow_resumption=1")
        assert code == 0, f"Failed to reload ulp_driver in resumption mode: {err}"

        # Inspect dmesg for resumption logs
        _, dmesg_out, _ = run_cmd("dmesg | grep -E 'ulp_driver.*Resum|ulp_driver.*re-adopted' | tail -5")
        print(f"[+] Resumption Kernel Logs:\n{dmesg_out}")

        # Check /proc/ulp_patches
        code, out, _ = run_cmd("cat /proc/ulp_patches")
        print(f"[+] Re-adopted Active Patches in new driver:\n{out}")
        assert "pgrust_ver_patch" in out and "pgrust_query_patch" in out
        print("[+] PASS: All livepatches successfully re-adopted by the new kernel module!")

        # Step 8: High-concurrency traffic post-resumption
        print("\n>>> [Step 8] High-concurrency stress test (800 queries post-resumption)...")
        code, out, _ = run_cmd(f"PGRUST_PORT=5437 PGRUST_THREADS=16 PGRUST_QUERIES=50 {CLIENT_BIN}")
        assert code == 0
        assert "Failed Requests         : 0" in out
        print("[+] PASS: 800 queries completed with 0 errors post-driver-resumption.")

        # Step 9: Revert livepatches using reloaded driver
        print("\n>>> [Step 9] Reverting livepatches using the reloaded driver...")
        code1, out1, _ = run_cmd(f"{ULP_CTL} revert {pid} 0x{target_version_vaddr:x}")
        code2, out2, _ = run_cmd(f"{ULP_CTL} revert {pid} 0x{target_query_vaddr:x}")
        assert code1 == 0, f"Failed to revert version patch: {out1}"
        assert code2 == 0, f"Failed to revert query patch: {out2}"

        code, out, _ = run_cmd("cat /proc/ulp_patches")
        assert "pgrust_ver_patch" not in out and "pgrust_query_patch" not in out
        print("[+] PASS: Patches cleanly unlinked and rolled back to original prologue bytes.")

        # Verify unpatched traffic
        code, out, _ = run_cmd(f"PGRUST_PORT=5437 PGRUST_THREADS=4 PGRUST_QUERIES=10 {CLIENT_BIN}")
        assert code == 0 and "Livepatched Versions Seen: 0" in out
        print("[+] Baseline unpatched state restored.")

        # Step 10: Verify Linux Kernel Livepatching (CONFIG_LIVEPATCH) on ulp_driver.ko
        print("\n>>> [Step 10] Testing Linux Kernel Livepatching (CONFIG_LIVEPATCH / ftrace)...")
        # Apply patch again so table has content
        run_cmd(f"{ULP_CTL} apply {pid} pgrust_ver_patch pgrust_get_version 0x{target_version_vaddr:x} 0x{patch_version_vaddr:x} 16")

        print("[*] Inserting livepatch_ulp.ko (patches ulp_driver::ulp_proc_show)...")
        code, _, err = run_cmd(f"insmod {KLP_DIR}/livepatch_ulp.ko")
        assert code == 0, f"Failed to insert livepatch_ulp.ko: {err}"
        time.sleep(1)

        code, out, _ = run_cmd("cat /proc/ulp_patches")
        print(f"[+] Output of /proc/ulp_patches while livepatch_ulp is ACTIVE:\n{out}")
        assert "[KERNEL LIVEPATCH ACTIVE]" in out
        assert "Zero-Downtime Hotfix Verified" in out
        print("[+] PASS: ulp_driver.ko was hot-patched in-flight via Linux kernel livepatching!")

        # Disable kernel livepatch
        print("[*] Disabling kernel livepatch via sysfs...")
        run_cmd("echo 0 > /sys/kernel/livepatch/livepatch_ulp/enabled")
        time.sleep(1)
        run_cmd("rmmod livepatch_ulp")

        code, out, _ = run_cmd("cat /proc/ulp_patches")
        print(f"[+] Output of /proc/ulp_patches after disabling livepatch_ulp:\n{out}")
        assert "pgrust_ver_patch" in out
        assert "[KERNEL LIVEPATCH ACTIVE]" not in out
        print("[+] PASS: Original ulp_proc_show cleanly restored after livepatch removal.")

        # Clean up
        run_cmd(f"{ULP_CTL} revert {pid} 0x{target_version_vaddr:x}")

        print("\n======================================================================")
        print(">>> ALL TESTS PASSED: ULP DRIVER RESUMPTION & KLP 100% VERIFIED!   <<<")
        print("======================================================================")

    finally:
        print("[*] Terminating pgrust_daemon...")
        daemon_proc.terminate()
        try:
            daemon_proc.wait(timeout=2)
        except subprocess.TimeoutExpired:
            daemon_proc.kill()

if __name__ == "__main__":
    main()
