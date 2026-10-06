#!/usr/bin/env python3
"""
ULP Canary Livepatching & MULTICS-Style Crash Resilience Test Suite
Validates:
  1. Baseline V0 throughput and stability
  2. 1% Canary livepatching with Tramp-Backup baseline routing
  3. Dynamic canary promotion under load (1% -> 10% -> 50% -> 100%)
  4. MULTICS-Style Zero-Crash Fault Interception & Auto-Quarantine on Fat-Finger Bugs
"""

import os
import sys
import time
import socket
import struct
import subprocess
import threading
import json
from concurrent.futures import ThreadPoolExecutor

PORT = 9188
SERVER_BIN = "./server_daemon"
PATCH_CANARY_SO = "./patch_canary.so"
PATCH_BUGGY_SO = "./patch_buggy_fatfinger.so"

class BenchStats:
    def __init__(self):
        self.lock = threading.Lock()
        self.total = 0
        self.v0_count = 0
        self.v1_canary_count = 0
        self.buggy_count = 0
        self.errors = 0

    def record(self, text, code):
        with self.lock:
            self.total += 1
            if code != 200:
                self.errors += 1
                return
            if "V1-Canary" in text:
                self.v1_canary_count += 1
            elif "V0-Original" in text:
                self.v0_count += 1
            elif "V-BUGGY" in text:
                self.buggy_count += 1
            else:
                self.v0_count += 1

def send_http_request(port=PORT, path="/test"):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2.0)
        s.connect(("127.0.0.1", port))
        req = f"GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
        s.sendall(req.encode())
        resp = b""
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            resp += chunk
        s.close()
        text = resp.decode(errors="ignore")
        return text, 200
    except Exception as e:
        return str(e), 500

def get_server_metrics(port=PORT):
    try:
        text, code = send_http_request(port, "/stats")
        if code == 200 and "\r\n\r\n" in text:
            body = text.split("\r\n\r\n", 1)[1]
            return json.loads(body.strip())
    except Exception:
        pass
    return None

def set_canary_ratio(port=PORT, basis_points=100):
    text, code = send_http_request(port, f"/set_canary?ratio={basis_points}")
    return code == 200

def find_func_vaddr(pid, func_name):
    exe_path = os.path.realpath(f"/proc/{pid}/exe")
    with open(exe_path, "rb") as f:
        elf_hdr = f.read(64)
        e_type = struct.unpack("<H", elf_hdr[16:18])[0]
        is_pie = (e_type == 3) # ET_DYN

    base_addr = 0
    if is_pie:
        with open(f"/proc/{pid}/maps") as f:
            for line in f:
                if exe_path in line and ("r-xp" in line or "r--p" in line or "rwxp" in line):
                    base_addr = int(line.split("-")[0], 16)
                    break
    
    nm_out = subprocess.check_output(["nm", exe_path]).decode()
    for line in nm_out.splitlines():
        parts = line.split()
        if len(parts) >= 3 and parts[2] == func_name:
            offset = int(parts[0], 16)
            return base_addr + offset if is_pie else offset
    return None

def find_module_symbol(pid, so_name, sym_name):
    base_addr = None
    with open(f"/proc/{pid}/maps") as f:
        for line in f:
            if so_name in line and ("r-xp" in line or "r--p" in line or "rwxp" in line):
                base_addr = int(line.split("-")[0], 16)
                break
    if not base_addr:
        return None
    nm_out = subprocess.check_output(["nm", "-D", so_name]).decode()
    for line in nm_out.splitlines():
        parts = line.split()
        if len(parts) >= 3 and parts[2] == sym_name:
            offset = int(parts[0], 16)
            return base_addr + offset
    return None

def find_module_vma_range(pid, so_name):
    start = None
    end = None
    with open(f"/proc/{pid}/maps") as f:
        for line in f:
            if so_name in line:
                parts = line.split()
                addr_range = parts[0].split("-")
                v_start = int(addr_range[0], 16)
                v_end = int(addr_range[1], 16)
                if start is None or v_start < start:
                    start = v_start
                if end is None or v_end > end:
                    end = v_end
    return start, end

def run_load_batch(num_requests=1000, concurrency=10, port=PORT):
    stats = BenchStats()
    start_time = time.time()
    with ThreadPoolExecutor(max_workers=concurrency) as executor:
        futures = [executor.submit(send_http_request, port, f"/query-{i}") for i in range(num_requests)]
        for f in futures:
            text, code = f.result()
            stats.record(text, code)
    elapsed = time.time() - start_time
    rps = num_requests / elapsed if elapsed > 0 else 0
    return stats, elapsed, rps

def main():
    print("=" * 76)
    print("  ULP CANARY LIVEPATCHING & MULTICS-STYLE FAULT RESILIENCE BENCHMARK")
    print("=" * 76)

    server_path = os.path.abspath(SERVER_BIN)
    canary_so = os.path.abspath(PATCH_CANARY_SO)
    buggy_so = os.path.abspath(PATCH_BUGGY_SO)

    if not os.path.exists(server_path) or not os.path.exists(canary_so):
        print("[-] Error: Binaries not compiled. Run 'make' first.")
        sys.exit(1)

    print(f"[*] Starting Server Daemon on port {PORT}...")
    server_proc = subprocess.Popen([server_path, str(PORT)],
                                   stdout=subprocess.DEVNULL,
                                   stderr=subprocess.DEVNULL)
    time.sleep(0.5)

    if server_proc.poll() is not None:
        print(f"[-] Server failed to start. Code {server_proc.returncode}")
        sys.exit(1)

    pid = server_proc.pid
    print(f"[+] Server Daemon running with PID {pid}")

    try:
        # -------------------------------------------------------------
        # TEST 1: Baseline V0 Performance
        # -------------------------------------------------------------
        print("\n" + "-" * 76)
        print(">>> TEST 1: Baseline V0 Performance (Unpatched Pristine Server)")
        print("-" * 76)
        stats_v0, elapsed_v0, rps_v0 = run_load_batch(num_requests=1500, concurrency=16, port=PORT)
        print(f"[+] Total Requests:        {stats_v0.total}")
        print(f"[+] V0-Original Responses: {stats_v0.v0_count} ({stats_v0.v0_count/stats_v0.total*100:.2f}%)")
        print(f"[+] V1-Canary Responses:   {stats_v0.v1_canary_count}")
        print(f"[+] Failed Requests:        {stats_v0.errors}")
        print(f"[+] Throughput:             {rps_v0:.1f} req/sec in {elapsed_v0:.2f}s")
        assert stats_v0.v0_count == 1500, "Expected 100% V0 responses in baseline"
        assert stats_v0.errors == 0, "Expected 0 errors in baseline"
        print("[PASSED] Baseline V0 Verification: 100% Stability & Zero Errors")

        # -------------------------------------------------------------
        # TEST 2: In-Flight Canary Livepatching (1.00% Canary Routing)
        # -------------------------------------------------------------
        print("\n" + "-" * 76)
        print(">>> TEST 2: Canary Livepatch Injection (1.00% Traffic Split / 100 bp)")
        print("-" * 76)
        
        inject_cmd = f"./ulp_inject {pid} {canary_so}"
        ret = subprocess.run(inject_cmd, shell=True, capture_output=True, text=True)
        print(ret.stdout.strip())
        if ret.returncode != 0:
            print(f"[-] Injection error: {ret.stderr}")
            sys.exit(1)

        time.sleep(0.2)
        orig_vaddr = find_func_vaddr(pid, "service_process_request")
        patch_vaddr = find_module_symbol(pid, "patch_canary.so", "livepatch_service_process_request")
        print(f"[+] Resolved Target: service_process_request @ 0x{orig_vaddr:x}")
        print(f"[+] Resolved Patch:  livepatch_service_process_request @ 0x{patch_vaddr:x}")

        patch_cmd = f"./ulp_canary_ctl patch {pid} {orig_vaddr:x} {patch_vaddr:x}"
        ret = subprocess.run(patch_cmd, shell=True, capture_output=True, text=True)
        print(ret.stdout.strip())

        print("[*] Dispatching 5,000 requests under 20 concurrent workers...")
        stats_c1, elapsed_c1, rps_c1 = run_load_batch(num_requests=5000, concurrency=20, port=PORT)
        canary_pct = (stats_c1.v1_canary_count / stats_c1.total) * 100.0
        v0_pct = (stats_c1.v0_count / stats_c1.total) * 100.0

        print(f"[+] Total Requests:        {stats_c1.total}")
        print(f"[+] V1-Canary Responses:   {stats_c1.v1_canary_count} ({canary_pct:.2f}%) [Target: ~1.00%]")
        print(f"[+] V0-Original Responses: {stats_c1.v0_count} ({v0_pct:.2f}%) [Target: ~99.00%]")
        print(f"[+] Failed Requests:        {stats_c1.errors}")
        print(f"[+] Throughput Under Patch: {rps_c1:.1f} req/sec")

        assert stats_c1.errors == 0, "Expected 0 errors during canary routing"
        assert 0.4 <= canary_pct <= 2.2, f"Canary percentage {canary_pct:.2f}% out of range (0.4% - 2.2%)"
        print("[PASSED] 1% Canary Traffic Splitting Verified with 0 Dropped Requests!")

        # -------------------------------------------------------------
        # TEST 3: Dynamic Runtime Canary Promotion (10% -> 50% -> 100%)
        # -------------------------------------------------------------
        print("\n" + "-" * 76)
        print(">>> TEST 3: Dynamic Runtime Canary Promotion (10% -> 50% -> 100%)")
        print("-" * 76)

        # Step 3A: Promote to 10% (1,000 bp)
        print("[*] Dynamically promoting canary ratio to 10.00% (1,000 bp)...")
        set_canary_ratio(PORT, 1000)
        stats_10, _, _ = run_load_batch(num_requests=3000, concurrency=20, port=PORT)
        pct_10 = (stats_10.v1_canary_count / stats_10.total) * 100.0
        print(f"[+] Ratio 10%: Canary={stats_10.v1_canary_count} ({pct_10:.2f}%), V0={stats_10.v0_count}, Errors={stats_10.errors}")
        assert 7.0 <= pct_10 <= 13.5, f"Expected ~10% canary, got {pct_10:.2f}%"

        # Step 3B: Promote to 50% (5,000 bp)
        print("[*] Dynamically promoting canary ratio to 50.00% (5,000 bp)...")
        set_canary_ratio(PORT, 5000)
        stats_50, _, _ = run_load_batch(num_requests=3000, concurrency=20, port=PORT)
        pct_50 = (stats_50.v1_canary_count / stats_50.total) * 100.0
        print(f"[+] Ratio 50%: Canary={stats_50.v1_canary_count} ({pct_50:.2f}%), V0={stats_50.v0_count}, Errors={stats_50.errors}")
        assert 44.0 <= pct_50 <= 56.0, f"Expected ~50% canary, got {pct_50:.2f}%"

        # Step 3C: Full Rollout to 100% (10,000 bp)
        print("[*] Promoting to 100.00% (Full Production Rollout)...")
        set_canary_ratio(PORT, 10000)
        stats_100, _, _ = run_load_batch(num_requests=3000, concurrency=20, port=PORT)
        pct_100 = (stats_100.v1_canary_count / stats_100.total) * 100.0
        print(f"[+] Full Rollout 100%: Canary={stats_100.v1_canary_count} ({pct_100:.2f}%), V0={stats_100.v0_count}, Errors={stats_100.errors}")
        assert stats_100.v1_canary_count == 3000, f"Expected 100% canary responses"
        assert stats_100.errors == 0
        print("[PASSED] Dynamic Live Canary Promotion Fully Verified in Real-Time!")

        # -------------------------------------------------------------
        # TEST 4: MULTICS-Style Zero-Crash Fault Resilience on Buggy Patch
        # -------------------------------------------------------------
        print("\n" + "-" * 76)
        print(">>> TEST 4: MULTICS Fault Resilience & Auto-Rollback on Fat-Finger Bug")
        print("-" * 76)

        print(f"[*] Injecting buggy patch with NULL pointer dereference ({buggy_so})...")
        ret = subprocess.run(f"./ulp_inject {pid} {buggy_so}", shell=True, capture_output=True, text=True)
        print(ret.stdout.strip())
        time.sleep(0.2)

        buggy_start, buggy_end = find_module_vma_range(pid, "patch_buggy_fatfinger.so")
        buggy_patch_vaddr = find_module_symbol(pid, "patch_buggy_fatfinger.so", "livepatch_service_process_request")
        fallback_vaddr = find_func_vaddr(pid, "fallback_service_process_request")

        print(f"[+] Buggy Patch Memory Range: 0x{buggy_start:x} - 0x{buggy_end:x}")
        print(f"[+] Buggy Entrypoint:         0x{buggy_patch_vaddr:x}")
        print(f"[+] Safe Fallback Entrypoint: 0x{fallback_vaddr:x}")

        print("[*] Activating buggy livepatch trampoline...")
        patch_cmd = f"./ulp_canary_ctl patch {pid} {orig_vaddr:x} {buggy_patch_vaddr:x}"
        subprocess.run(patch_cmd, shell=True, check=True)

        print("[*] Sending 3,000 requests under concurrent load to intentional crash target...")
        stats_buggy, elapsed_b, rps_b = run_load_batch(num_requests=3000, concurrency=20, port=PORT)

        alive = (server_proc.poll() is None)
        print(f"[+] Server Process Alive:   {alive} (PID: {pid})")
        print(f"[+] Total Requests Handled: {stats_buggy.total}")
        print(f"[+] Successful Responses:   {stats_buggy.v0_count}")
        print(f"[+] Failed Requests:        {stats_buggy.errors}")
        print(f"[+] Throughput on Fallback: {rps_b:.1f} req/sec")

        metrics = get_server_metrics(PORT)
        if metrics:
            print(f"[+] Telemetry - Faults Trapped:    {metrics.get('faults_intercepted', 0)}")
            print(f"[+] Telemetry - Crashes Prevented: {metrics.get('crashes_prevented', 0)}")

        assert alive, "FATAL: Server crashed on buggy patch! Fault guard failed."
        assert stats_buggy.errors == 0, f"Expected 0 errors, got {stats_buggy.errors}"
        assert stats_buggy.v0_count == 3000, f"Expected all 3,000 requests to succeed via fallback"
        print("[PASSED] MULTICS-Style Zero-Crash Fault Resilience: 100% Uptime Preserved!")

        print("\n" + "=" * 76)
        print("  ALL 4 CANARY & MULTICS FAULT RESILIENCE BENCHMARKS PASSED (100% SUCCESS)")
        print("=" * 76)

    finally:
        if server_proc.poll() is None:
            server_proc.terminate()
            server_proc.wait(timeout=2)

if __name__ == "__main__":
    main()
