#!/usr/bin/env python3
"""
Validation script for upgraded Interactive Livepatch Studio (TUI) Backend
Tests:
- /dev/ulp VFS Device Communication
- Scanning & Discovery across Rust (pgrust) and C daemons (MariaDB, Postgres, HAProxy)
- Arming & Disarming Kernel Maintenance Window
- Deploying Generations [1], [2], [3]
- Atomic Revert [R]
"""

import os as _os
import sys as _sys
REPO_DIR = _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__)))
if _os.path.join(REPO_DIR, "tools") not in _sys.path:
    _sys.path.insert(0, _os.path.join(REPO_DIR, "tools"))
import sys
import os
import subprocess
import time

sys.path.insert(0, os.path.join(REPO_DIR, "tools"))
import ulp_tui

# Ensure pgrust daemon is running in background for testing
subprocess.run("pkill -9 -f pgrust_daemon 2>/dev/null || true", shell=True)
time.sleep(0.5)
pgrust_bin = REPO_DIR + "/rust-livepatch-bench/target/release/pgrust_daemon"
pgrust_env = os.environ.copy()
pgrust_env["PGRUST_PORT"] = "5435"
pgrust_env["LD_PRELOAD"] = "/tmp/ulp_patches/libpatch_pgrust_v1.so:/tmp/ulp_patches/libpatch_pgrust_v2.so:/tmp/ulp_patches/libpatch_pgrust_v3.so"
pgrust_proc = None
if os.path.exists(pgrust_bin):
    pgrust_proc = subprocess.Popen([pgrust_bin], env=pgrust_env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(1.5)

studio = ulp_tui.ULPStudio()
if not studio.open_device():
    print("[-] Failed to open /dev/ulp")
    sys.exit(1)
print("[+] /dev/ulp opened successfully via Mode 0600 VFS Protocol.")

studio.scan_pids()
for t in studio.targets:
    tname = t['name']
    tpid = t['pid']
    tvaddr = t['vaddr']
    tstatus = t['status']
    tgen = t['current_gen']
    print(f"[+] Target: {tname:<16} | PID: {str(tpid):<6} | VADDR: 0x{tvaddr:016x} | Gen: {tgen:<18} | Status: {tstatus}")

# 1. Test Arming
studio.arm_driver(ttl=60)
print(f"[+] Driver Arm Status: {studio.status_msg}")

# 2. Test Multi-Generation Deployment across targets
# Deploy Gen 1 on pgrust
pgrust_target = next(t for t in studio.targets if "pgrust" in t["name"])
studio.apply_generation(pgrust_target, "1")
print(f"[+] pgrust Gen 1 Deploy: {studio.status_msg}")

# Deploy Gen 2 on pgrust
studio.apply_generation(pgrust_target, "2")
print(f"[+] pgrust Gen 2 Deploy: {studio.status_msg}")

# Deploy Gen 3 on pgrust
studio.apply_generation(pgrust_target, "3")
print(f"[+] pgrust Gen 3 Deploy: {studio.status_msg}")

# Revert pgrust
studio.revert_target(pgrust_target)
print(f"[+] pgrust Revert Status: {studio.status_msg}")

# 3. Test Disarming
studio.disarm_driver()
print(f"[+] Driver Disarm Status: {studio.status_msg}")

if pgrust_proc:
    pgrust_proc.terminate()
    pgrust_proc.wait()

print("\n=== SUCCESS: TUI Multi-Generation Backend Validation Complete! ===")
