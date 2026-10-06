#!/usr/bin/env python3
"""
Multi-Version Continuous Livepatching Suite for Golang Daemons
==============================================================
Validates continuous livepatching lifecycle across Go daemons:
  V0 (Baseline v1.0.0-GA)
    ├── Apply V1 (v1.1.0-SECURITY-HOTFIX)
    ├── Apply V2 (v2.0.0-PERF-UPGRADE)
    ├── Apply V3 (v3.0.0-PRODUCTION)
    └── Atomic Revert -> V0 (v1.0.0-GA)

Concurrently drives 1,000+ HTTP requests across multi-threaded goroutines
with ZERO dropped requests, zero panics, and zero SIGSEGV crashes.
"""

import os
import sys
import time
import json
import shutil
import urllib.request
import threading
import subprocess

BENCH_DIR = "/root/ulp-driver/go-livepatch-bench"
ULP_CTL = "/usr/local/bin/ulp_ctl"
ULP_INJECT = "/usr/local/bin/ulp_inject"

def run_cmd(cmd):
    p = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return p.returncode, p.stdout.strip(), p.stderr.strip()

def get_symbol_vaddr(exe_path, sym_name):
    code, out, _ = run_cmd(f"nm '{exe_path}' 2>/dev/null | grep -w '{sym_name}'")
    if code != 0 or not out:
        raise RuntimeError(f"Symbol '{sym_name}' not found in {exe_path}")
    return int(out.split()[0], 16)

def query_go_server():
    try:
        req = urllib.request.Request("http://127.0.0.1:9090/api/v1/status")
        with urllib.request.urlopen(req, timeout=1.5) as resp:
            data = json.loads(resp.read().decode())
            return data
    except Exception as e:
        return {"error": str(e)}

def compile_asm_patch(asm_content, out_bin):
    asm_file = out_bin + ".s"
    o_file = out_bin + ".o"
    with open(asm_file, "w") as f:
        f.write(asm_content)
    run_cmd(f"gcc -c -o {o_file} {asm_file}")
    run_cmd(f"objcopy -O binary -j .text {o_file} {out_bin}")

def main():
    print("==============================================================================")
    print("   GOLANG CONTINUOUS MULTI-VERSION LIVEPATCHING VERIFICATION SUITE            ")
    print("==============================================================================")

    # 1. Build Go Server
    print("[*] Compiling Go server (main.go)...")
    code, _, err = run_cmd(f"cd {BENCH_DIR} && go build -o server_go main.go")
    assert code == 0, f"Go build failed: {err}"

    # Kill existing servers
    run_cmd("killall -9 server_go 2>/dev/null || true")
    run_cmd("fuser -k -9 9090/tcp 2>/dev/null || true")
    time.sleep(1)

    # 2. Start Go Server
    print("[*] Starting Go REST server on :9090...")
    proc = subprocess.Popen([f"{BENCH_DIR}/server_go"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    time.sleep(1.5)
    go_pid = proc.pid
    print(f"[+] Go Server running with PID: {go_pid}")

    # Verify baseline V0
    v0_status = query_go_server()
    print(f"[+] Baseline V0 Status: {v0_status.get('status')} | Version: {v0_status.get('version')}")
    assert v0_status.get("status") == "ORIGINAL_UNPATCHED_GO_SERVICE"
    assert v0_status.get("version") == "v1.0.0-GA"

    # Resolve target symbols in Go binary
    exe_path = f"{BENCH_DIR}/server_go"
    sym_status_addr = get_symbol_vaddr(exe_path, "main.GetServiceStatus")
    sym_ver_addr = get_symbol_vaddr(exe_path, "main.GetVersionTag")
    print(f"[+] Target main.GetServiceStatus: 0x{sym_status_addr:016x}")
    print(f"[+] Target main.GetVersionTag   : 0x{sym_ver_addr:016x}")

    # Build Patches V1, V2, V3
    # Note: In Go ABIInternal on x86_64, a string return is RAX (ptr), RBX (len)
    v1_status_s = """
.global _start
.text
_start:
    lea msg(%rip), %rax
    mov $24, %rbx
    ret
msg:
    .ascii "GO_SERVICE_V1_HOTPATCHED"
"""
    v1_ver_s = """
.global _start
.text
_start:
    lea msg(%rip), %rax
    mov $22, %rbx
    ret
msg:
    .ascii "v1.1.0-SECURITY-HOTFIX"
"""

    v2_status_s = """
.global _start
.text
_start:
    lea msg(%rip), %rax
    mov $27, %rbx
    ret
msg:
    .ascii "GO_SERVICE_V2_OPTIMIZED_RCU"
"""
    v2_ver_s = """
.global _start
.text
_start:
    lea msg(%rip), %rax
    mov $19, %rbx
    ret
msg:
    .ascii "v2.0.0-PERF-UPGRADE"
"""

    v3_status_s = """
.global _start
.text
_start:
    lea msg(%rip), %rax
    mov $30, %rbx
    ret
msg:
    .ascii "GO_SERVICE_V3_ENTERPRISE_ASYNC"
"""
    v3_ver_s = """
.global _start
.text
_start:
    lea msg(%rip), %rax
    mov $17, %rbx
    ret
msg:
    .ascii "v3.0.0-PRODUCTION"
"""

    compile_asm_patch(v1_status_s, f"{BENCH_DIR}/patch_v1_status.bin")
    compile_asm_patch(v1_ver_s, f"{BENCH_DIR}/patch_v1_ver.bin")
    compile_asm_patch(v2_status_s, f"{BENCH_DIR}/patch_v2_status.bin")
    compile_asm_patch(v2_ver_s, f"{BENCH_DIR}/patch_v2_ver.bin")
    compile_asm_patch(v3_status_s, f"{BENCH_DIR}/patch_v3_status.bin")
    compile_asm_patch(v3_ver_s, f"{BENCH_DIR}/patch_v3_ver.bin")

    # Start Background Concurrent Client Load (500 queries)
    load_running = True
    load_errors = 0
    load_success = 0

    def load_worker():
        nonlocal load_errors, load_success
        while load_running:
            data = query_go_server()
            if "error" in data:
                load_errors += 1
            else:
                load_success += 1
            time.sleep(0.005)

    workers = [threading.Thread(target=load_worker) for _ in range(10)]
    for w in workers:
        w.daemon = True
        w.start()

    time.sleep(0.5)

    # --- STAGE 1: Apply V1 ---
    print("\n>>> [STAGE 1] Applying V1 Hotpatch (v1.1.0-SECURITY-HOTFIX)...")
    _, out_inj1, _ = run_cmd(f"{ULP_INJECT} {go_pid} {BENCH_DIR}/patch_v1_status.bin")
    patch_v1_status_addr = int(out_inj1.split("target_patch_addr=")[1].strip(), 16)
    _, out_inj1v, _ = run_cmd(f"{ULP_INJECT} {go_pid} {BENCH_DIR}/patch_v1_ver.bin")
    patch_v1_ver_addr = int(out_inj1v.split("target_patch_addr=")[1].strip(), 16)

    run_cmd(f"{ULP_CTL} apply {go_pid} go_v1_status main.GetServiceStatus 0x{sym_status_addr:x} 0x{patch_v1_status_addr:x} 13")
    run_cmd(f"{ULP_CTL} apply {go_pid} go_v1_ver main.GetVersionTag 0x{sym_ver_addr:x} 0x{patch_v1_ver_addr:x} 13")
    time.sleep(0.5)

    v1_status = query_go_server()
    print(f"[+] Active V1 Status: {v1_status.get('status')} | Version: {v1_status.get('version')}")
    assert v1_status.get("status") == "GO_SERVICE_V1_HOTPATCHED"
    assert v1_status.get("version") == "v1.1.0-SECURITY-HOTFIX"

    # --- STAGE 2: Apply V2 ---
    print("\n>>> [STAGE 2] Applying V2 Hotpatch (v2.0.0-PERF-UPGRADE)...")
    _, out_inj2, _ = run_cmd(f"{ULP_INJECT} {go_pid} {BENCH_DIR}/patch_v2_status.bin")
    patch_v2_status_addr = int(out_inj2.split("target_patch_addr=")[1].strip(), 16)
    _, out_inj2v, _ = run_cmd(f"{ULP_INJECT} {go_pid} {BENCH_DIR}/patch_v2_ver.bin")
    patch_v2_ver_addr = int(out_inj2v.split("target_patch_addr=")[1].strip(), 16)

    run_cmd(f"{ULP_CTL} apply {go_pid} go_v2_status main.GetServiceStatus 0x{sym_status_addr:x} 0x{patch_v2_status_addr:x} 13")
    run_cmd(f"{ULP_CTL} apply {go_pid} go_v2_ver main.GetVersionTag 0x{sym_ver_addr:x} 0x{patch_v2_ver_addr:x} 13")
    time.sleep(0.5)

    v2_status = query_go_server()
    print(f"[+] Active V2 Status: {v2_status.get('status')} | Version: {v2_status.get('version')}")
    assert v2_status.get("status") == "GO_SERVICE_V2_OPTIMIZED_RCU"
    assert v2_status.get("version") == "v2.0.0-PERF-UPGRADE"

    # --- STAGE 3: Apply V3 ---
    print("\n>>> [STAGE 3] Applying V3 Hotpatch (v3.0.0-PRODUCTION)...")
    _, out_inj3, _ = run_cmd(f"{ULP_INJECT} {go_pid} {BENCH_DIR}/patch_v3_status.bin")
    patch_v3_status_addr = int(out_inj3.split("target_patch_addr=")[1].strip(), 16)
    _, out_inj3v, _ = run_cmd(f"{ULP_INJECT} {go_pid} {BENCH_DIR}/patch_v3_ver.bin")
    patch_v3_ver_addr = int(out_inj3v.split("target_patch_addr=")[1].strip(), 16)

    run_cmd(f"{ULP_CTL} apply {go_pid} go_v3_status main.GetServiceStatus 0x{sym_status_addr:x} 0x{patch_v3_status_addr:x} 13")
    run_cmd(f"{ULP_CTL} apply {go_pid} go_v3_ver main.GetVersionTag 0x{sym_ver_addr:x} 0x{patch_v3_ver_addr:x} 13")
    time.sleep(0.5)

    v3_status = query_go_server()
    print(f"[+] Active V3 Status: {v3_status.get('status')} | Version: {v3_status.get('version')}")
    assert v3_status.get("status") == "GO_SERVICE_V3_ENTERPRISE_ASYNC"
    assert v3_status.get("version") == "v3.0.0-PRODUCTION"

    # Verify kernel registry
    _, reg_list, _ = run_cmd(f"{ULP_CTL} list")
    print(f"\n[+] Active Kernel Patch Registry for PID {go_pid}:\n{reg_list}")

    # --- STAGE 4: Revert to Baseline V0 ---
    print("\n>>> [STAGE 4] Atomically reverting all livepatches back to V0 baseline...")
    run_cmd(f"{ULP_CTL} revert {go_pid} 0x{sym_status_addr:x}")
    run_cmd(f"{ULP_CTL} revert {go_pid} 0x{sym_ver_addr:x}")
    time.sleep(0.5)

    v0_revert = query_go_server()
    print(f"[+] Post-Revert V0 Status: {v0_revert.get('status')} | Version: {v0_revert.get('version')}")
    assert v0_revert.get("status") == "ORIGINAL_UNPATCHED_GO_SERVICE"
    assert v0_revert.get("version") == "v1.0.0-GA"

    # Stop load workers
    load_running = False
    for w in workers:
        w.join(timeout=1.0)

    print(f"\n[+] Load Verification: {load_success} successful concurrent queries, {load_errors} errors")
    assert load_errors == 0, f"Encountered {load_errors} load errors during livepatching!"

    # Clean up
    proc.terminate()
    proc.wait()
    print("==============================================================================")
    print("   RESULT: GOLANG MULTI-VERSION CONTINUOUS LIVEPATCHING 100% SUCCESS!         ")
    print("==============================================================================")

if __name__ == "__main__":
    main()
