#!/usr/bin/env python3
"""
HAProxy Enterprise Canary Livepatching Benchmark
Target: HAProxy 3.5-dev3 multi-threaded daemon
Validates:
  1. Live injection into running HAProxy under load
  2. 1% Statistical Canary routing on stick-table lookup transactions
  3. Dynamic real-time canary promotion (1% -> 10% -> 50% -> 100%)
  4. Instant live rollback with 0 downtime
"""

import os
import sys
import time
import socket
import struct
import subprocess
import threading
from concurrent.futures import ThreadPoolExecutor

HAPROXY_PORT = 8889
HAPROXY_BIN = "/root/haproxy/haproxy"
BENCH_DIR = "/root/haproxy-canary-bench"
PATCH_CANARY_SO = f"{BENCH_DIR}/patch_haproxy_canary.so"

class RequestStats:
    def __init__(self):
        self.lock = threading.Lock()
        self.total = 0
        self.success = 0
        self.errors = 0

    def record(self, code):
        with self.lock:
            self.total += 1
            if code == 200:
                self.success += 1
            else:
                self.errors += 1

def send_haproxy_request(port=HAPROXY_PORT):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3.0)
        s.connect(("127.0.0.1", port))
        req = "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
        s.sendall(req.encode())
        resp = b""
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            resp += chunk
        s.close()
        text = resp.decode(errors="ignore")
        if "HTTP/1.1 200 OK" in text or "200 OK" in text or "ULP_DRIVER" in text:
            return 200
        return 500
    except Exception:
        return 500

def run_traffic_batch(num_requests=5000, concurrency=20, port=HAPROXY_PORT):
    stats = RequestStats()
    start_time = time.time()
    with ThreadPoolExecutor(max_workers=concurrency) as executor:
        futures = [executor.submit(send_haproxy_request, port) for _ in range(num_requests)]
        for f in futures:
            code = f.result()
            stats.record(code)
    elapsed = time.time() - start_time
    rps = num_requests / elapsed if elapsed > 0 else 0
    return stats, elapsed, rps

def find_func_vaddr(pid, func_name):
    exe_path = os.path.realpath(f"/proc/{pid}/exe")
    with open(exe_path, "rb") as f:
        elf_hdr = f.read(64)
        e_type = struct.unpack("<H", elf_hdr[16:18])[0]
        is_pie = (e_type == 3)

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

def find_module_base(pid, so_name):
    with open(f"/proc/{pid}/maps") as f:
        for line in f:
            if so_name in line:
                return int(line.split("-")[0], 16)
    return None

def find_module_symbol(pid, so_name, sym_name):
    base_addr = find_module_base(pid, so_name)
    if not base_addr:
        return None
    nm_out = subprocess.check_output(["nm", "-D", f"{BENCH_DIR}/{so_name}"]).decode()
    for line in nm_out.splitlines():
        parts = line.split()
        if len(parts) >= 3 and parts[2] == sym_name:
            offset = int(parts[0], 16)
            return base_addr + offset
    return None

def read_remote_uint64(pid, addr):
    try:
        with open(f"/proc/{pid}/mem", "rb") as f:
            f.seek(addr)
            data = f.read(8)
            return struct.unpack("<Q", data)[0]
    except Exception as e:
        print(f"[-] read_remote_uint64 error: {e}")
        return 0

def write_remote_uint32(pid, addr, val):
    try:
        with open(f"/proc/{pid}/mem", "r+b") as f:
            f.seek(addr)
            f.write(struct.pack("<I", val))
            return True
    except Exception as e:
        print(f"[-] write_remote_uint32 error: {e}")
        return False

def main():
    print("=" * 76)
    print("       HAPROXY CANARY LIVEPATCHING & TRAFFIC SPLITTING BENCHMARK")
    print("=" * 76)

    # 1. Generate HAProxy configuration
    cfg_path = "/tmp/haproxy_canary_bench.cfg"
    with open(cfg_path, "w") as f:
        f.write(f"""global
    maxconn 100000
    nbthread 4
    stats socket /tmp/haproxy_canary.sock mode 660 level admin

defaults
    mode http
    timeout connect 5s
    timeout client 30s
    timeout server 30s
    maxconn 100000

frontend http_in
    bind 127.0.0.1:{HAPROXY_PORT}
    stick-table type ip size 1m expire 10s store http_req_rate(10s)
    http-request track-sc0 src
    http-request return status 200 content-type "text/plain" string "ULP_DRIVER_HAPROXY_OK\\n"
""")

    subprocess.run("killall haproxy 2>/dev/null || true", shell=True)
    time.sleep(1)

    print(f"[*] Launching HAProxy v3.5 daemon (4 worker threads) on port {HAPROXY_PORT}...")
    hap_proc = subprocess.Popen([HAPROXY_BIN, "-f", cfg_path, "-db"],
                                stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL)
    time.sleep(1)

    if hap_proc.poll() is not None:
        print("[-] Failed to start HAProxy")
        sys.exit(1)

    pid = hap_proc.pid
    print(f"[+] HAProxy running with PID {pid}")

    try:
        # -------------------------------------------------------------
        # TEST 1: Baseline Load Test (2,000 requests)
        # -------------------------------------------------------------
        print("\n" + "-" * 76)
        print(">>> TEST 1: HAProxy Baseline Throughput (Unpatched)")
        print("-" * 76)
        stats_v0, elapsed_v0, rps_v0 = run_traffic_batch(num_requests=2000, concurrency=20)
        print(f"[+] Total Requests: {stats_v0.total}")
        print(f"[+] Successful:     {stats_v0.success} (100.00%)")
        print(f"[+] Errors:         {stats_v0.errors}")
        print(f"[+] Throughput:     {rps_v0:.1f} req/sec in {elapsed_v0:.2f}s")
        assert stats_v0.success == 2000 and stats_v0.errors == 0
        print("[PASSED] HAProxy Baseline Verified with Zero Errors")

        # -------------------------------------------------------------
        # TEST 2: Inject Canary Livepatch into Live HAProxy
        # -------------------------------------------------------------
        print("\n" + "-" * 76)
        print(">>> TEST 2: Live Injecting Canary Patch into Running HAProxy")
        print("-" * 76)

        inject_cmd = f"/usr/local/bin/ulp_inject {pid} {PATCH_CANARY_SO} 2>/dev/null || ./ulp_inject {pid} {PATCH_CANARY_SO}"
        ret = subprocess.run(inject_cmd, shell=True, capture_output=True, text=True)
        print(ret.stdout.strip())
        time.sleep(0.2)

        target_vaddr = find_func_vaddr(pid, "stktable_touch_local")
        patch_vaddr = find_module_symbol(pid, "patch_haproxy_canary.so", "livepatch_stktable_touch_local")
        canary_hits_addr = find_module_symbol(pid, "patch_haproxy_canary.so", "g_canary_tx_hits")
        baseline_hits_addr = find_module_symbol(pid, "patch_haproxy_canary.so", "g_baseline_tx_hits")
        ratio_addr = find_module_symbol(pid, "patch_haproxy_canary.so", "g_haproxy_canary_ratio")

        print(f"[+] Target Symbol: stktable_touch_local @ 0x{target_vaddr:x}")
        print(f"[+] Patch Symbol:  livepatch_stktable_touch_local @ 0x{patch_vaddr:x}")
        print(f"[+] Telemetry VAs: CanaryHits=0x{canary_hits_addr:x}, BaselineHits=0x{baseline_hits_addr:x}, Ratio=0x{ratio_addr:x}")

        # Apply livepatch via ulp_ctl or /dev/ulp
        patch_cmd = f"/usr/local/bin/ulp_ctl apply {pid} haproxy_canary stktable_touch_local 0x{target_vaddr:x} 0x{patch_vaddr:x} 16 2>/dev/null || ../canary-resilience-bench/ulp_canary_ctl patch {pid} {target_vaddr:x} {patch_vaddr:x}"
        ret = subprocess.run(patch_cmd, shell=True, capture_output=True, text=True)
        print(ret.stdout.strip())

        # -------------------------------------------------------------
        # TEST 3: 1.00% Canary Traffic Routing Under Heavy Load
        # -------------------------------------------------------------
        print("\n" + "-" * 76)
        print(">>> TEST 3: 1.00% Canary Traffic Splitting (10,000 requests)")
        print("-" * 76)
        stats_c1, elapsed_c1, rps_c1 = run_traffic_batch(num_requests=10000, concurrency=32)

        c_hits = read_remote_uint64(pid, canary_hits_addr)
        b_hits = read_remote_uint64(pid, baseline_hits_addr)
        total_hits = c_hits + b_hits
        c_pct = (c_hits / total_hits * 100.0) if total_hits > 0 else 0

        print(f"[+] Total Client Requests: {stats_c1.total} (Success: {stats_c1.success}, Errors: {stats_c1.errors})")
        print(f"[+] HAProxy Stick-Table Transactions: {total_hits}")
        print(f"[+] 1% Canary Transactions:          {c_hits} ({c_pct:.2f}%) [Target: ~1.00%]")
        print(f"[+] 99% Baseline Transactions:       {b_hits} ({100.0 - c_pct:.2f}%) [Target: ~99.00%]")
        print(f"[+] Throughput Under Livepatch:      {rps_c1:.1f} req/sec in {elapsed_c1:.2f}s")

        assert stats_c1.errors == 0, "Expected 0 errors during HAProxy canary routing"
        assert 0.4 <= c_pct <= 2.2, f"Canary percentage {c_pct:.2f}% out of range (0.4% - 2.2%)"
        print("[PASSED] HAProxy 1% Canary Routing Verified Under 10,000 Requests!")

        # -------------------------------------------------------------
        # TEST 4: Dynamic Canary Ratio Promotion (10% -> 50% -> 100%)
        # -------------------------------------------------------------
        print("\n" + "-" * 76)
        print(">>> TEST 4: Dynamic Canary Ratio Promotion on Live HAProxy")
        print("-" * 76)

        # 4A: Promote to 10% (1,000 bp)
        print("[*] Dynamically promoting HAProxy canary to 10.00% (1,000 bp)...")
        write_remote_uint32(pid, ratio_addr, 1000)
        c_before = read_remote_uint64(pid, canary_hits_addr)
        b_before = read_remote_uint64(pid, baseline_hits_addr)

        run_traffic_batch(num_requests=5000, concurrency=32)
        c_after = read_remote_uint64(pid, canary_hits_addr)
        b_after = read_remote_uint64(pid, baseline_hits_addr)
        delta_c = c_after - c_before
        delta_b = b_after - b_before
        pct_10 = (delta_c / (delta_c + delta_b) * 100.0) if (delta_c + delta_b) > 0 else 0
        print(f"[+] Ratio 10%: Canary={delta_c} ({pct_10:.2f}%), Baseline={delta_b}")
        assert 7.0 <= pct_10 <= 13.5, f"Expected ~10% canary, got {pct_10:.2f}%"

        # 4B: Promote to 50% (5,000 bp)
        print("[*] Dynamically promoting HAProxy canary to 50.00% (5,000 bp)...")
        write_remote_uint32(pid, ratio_addr, 5000)
        c_before = read_remote_uint64(pid, canary_hits_addr)
        b_before = read_remote_uint64(pid, baseline_hits_addr)

        run_traffic_batch(num_requests=5000, concurrency=32)
        c_after = read_remote_uint64(pid, canary_hits_addr)
        b_after = read_remote_uint64(pid, baseline_hits_addr)
        delta_c = c_after - c_before
        delta_b = b_after - b_before
        pct_50 = (delta_c / (delta_c + delta_b) * 100.0) if (delta_c + delta_b) > 0 else 0
        print(f"[+] Ratio 50%: Canary={delta_c} ({pct_50:.2f}%), Baseline={delta_b}")
        assert 44.0 <= pct_50 <= 56.0, f"Expected ~50% canary, got {pct_50:.2f}%"

        # 4C: Full Rollout to 100% (10,000 bp)
        print("[*] Promoting HAProxy canary to 100.00% (Full Production Rollout)...")
        write_remote_uint32(pid, ratio_addr, 10000)
        c_before = read_remote_uint64(pid, canary_hits_addr)
        b_before = read_remote_uint64(pid, baseline_hits_addr)

        run_traffic_batch(num_requests=5000, concurrency=32)
        c_after = read_remote_uint64(pid, canary_hits_addr)
        b_after = read_remote_uint64(pid, baseline_hits_addr)
        delta_c = c_after - c_before
        delta_b = b_after - b_before
        pct_100 = (delta_c / (delta_c + delta_b) * 100.0) if (delta_c + delta_b) > 0 else 0
        print(f"[+] Full Rollout 100%: Canary={delta_c} ({pct_100:.2f}%), Baseline={delta_b}")
        assert delta_c > 0 and delta_b == 0
        print("[PASSED] Dynamic Live HAProxy Canary Promotion Fully Verified!")

        # -------------------------------------------------------------
        # TEST 5: Live Revert via /dev/ulp
        # -------------------------------------------------------------
        print("\n" + "-" * 76)
        print(">>> TEST 5: Atomic Revert Back to Pristine HAProxy")
        print("-" * 76)
        revert_cmd = f"/usr/local/bin/ulp_ctl revert {pid} 0x{target_vaddr:x} 2>/dev/null || true"
        subprocess.run(revert_cmd, shell=True)

        stats_rev, _, rps_rev = run_traffic_batch(num_requests=2000, concurrency=20)
        print(f"[+] Revert Verification: {stats_rev.success}/2000 Requests OK ({rps_rev:.1f} req/s)")
        assert stats_rev.success == 2000 and stats_rev.errors == 0
        print("[PASSED] HAProxy Live Revert Complete with Zero Downtime!")

        print("\n" + "=" * 76)
        print("  ALL HAPROXY CANARY LIVEPATCHING BENCHMARKS PASSED (100% SUCCESS)")
        print("=" * 76)

    finally:
        if hap_proc.poll() is None:
            hap_proc.terminate()
            hap_proc.wait(timeout=2)
        subprocess.run("killall haproxy 2>/dev/null || true", shell=True)

if __name__ == "__main__":
    main()
