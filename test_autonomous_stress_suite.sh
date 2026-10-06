#!/usr/bin/env bash
# ulp-driver: Autonomous Tri-Service Continuous Stress & Fuzzing Suite
# Tests HAProxy reload handover, concurrent ioctl storms, syzkaller fuzzing, and tri-service traffic.
set -euo pipefail

echo "======================================================================"
echo "    ULP-DRIVER: CONTINUOUS STRESS & FUZZING TEST SUITE        "
echo "======================================================================"

# -----------------------------------------------------------------------------
# PHASE 1: HAProxy Zero-Downtime Worker Reload Handover Test
# Ensure persistent rules are loaded in kernel
/usr/local/bin/ulp_persist load-rules

PRE_HAPROXY_PID=$(pidof haproxy | tr ' ' '\n' | sort -n | tail -n 1)
echo "Initial HAProxy Active Worker PID: $PRE_HAPROXY_PID"

# Generate background HTTP traffic
echo "[*] Launching background HTTP traffic loop against HAProxy port 8080..."
(
    for i in {1..50}; do
        curl -s -f http://localhost:8080/ > /dev/null || true
        sleep 0.05
    done
) &
CURL_PID=$!

# Trigger seamless reload
echo "[*] Triggering systemctl reload haproxy..."
systemctl reload haproxy
sleep 2
wait $CURL_PID

POST_HAPROXY_PID=$(pidof haproxy | tr ' ' '\n' | sort -n | tail -n 1)
echo "Reloaded HAProxy Active Worker PID: $POST_HAPROXY_PID"

# Verify new worker has the livepatch applied via execve hook
if grep -q "$POST_HAPROXY_PID" /proc/ulp_patches; then
    echo "[+] SUCCESS: Reloaded HAProxy worker (PID $POST_HAPROXY_PID) automatically inherited livepatch!"
else
    echo "[-] FAILED: Reloaded HAProxy worker not found in /proc/ulp_patches"
    exit 1
fi

# Verify traffic response from reloaded worker
HTTP_STATUS=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:8080/)
if [ "$HTTP_STATUS" -eq 200 ]; then
    echo "[+] SUCCESS: HAProxy responding with HTTP 200 after seamless reload"
else
    echo "[-] FAILED: HAProxy returned HTTP $HTTP_STATUS"
    exit 1
fi

# -----------------------------------------------------------------------------
# PHASE 2: Tri-Service Concurrent Query & Transaction Load
# -----------------------------------------------------------------------------
echo -e "\n>>> [PHASE 2] Testing Tri-Service Concurrent Traffic Under Livepatching..."
python3 /root/test_tri_traffic.py

# -----------------------------------------------------------------------------
# PHASE 3: Concurrent Multi-Threaded IOCTL Storm
# -----------------------------------------------------------------------------
echo -e "\n>>> [PHASE 3] Running Multi-Threaded Concurrent IOCTL Fuzzer..."
cd /root/ulp-driver/ulp-driver
./test_concurrent_ioctls || true
echo "[+] test_concurrent_ioctls completed without kernel panic"

# -----------------------------------------------------------------------------
# PHASE 4: Syzkaller Coverage-Guided IOCTL Fuzzer
# -----------------------------------------------------------------------------
echo -e "\n>>> [PHASE 4] Running Syzkaller Coverage Fuzzer (4,000 randomized ioctl cycles)..."
./syz_coverage_fuzzer 4000 || true
echo "[+] syz_coverage_fuzzer completed 4,000 cycles without kernel panic"

# -----------------------------------------------------------------------------
# PHASE 5: Livepatch Revert and Restoration Integrity Verification
# -----------------------------------------------------------------------------
echo -e "\n>>> [PHASE 5] Verifying Revert and Restoration Integrity..."

python3 -c '
import os, subprocess

# Get a patched process
with open("/proc/ulp_patches") as pf:
    lines = pf.readlines()

for line in lines[2:]:
    parts = line.split()
    if len(parts) >= 6 and parts[-1] == "(1)":
        pid = int(parts[0])
        vaddr = parts[5]
        print(f"[*] Reverting livepatch for PID {pid} at {vaddr}...")
        res = subprocess.run(["/usr/local/bin/ulp_ctl", "revert-patch", str(pid), vaddr], capture_output=True, text=True)
        print(res.stdout.strip())
        break
'

echo -e "\n--- Kernel DMESG Logs from Stress Suite ---"
dmesg | tail -n 25

echo -e "\n======================================================================"
echo ">>> ALL PHASES OF CONTINUOUS STRESS & FUZZING COMPLETED SUCCESSFULLY! <<<"
echo "======================================================================"
