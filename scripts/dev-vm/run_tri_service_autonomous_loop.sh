#!/usr/bin/env bash
# ulp-driver: reboot-persistence test for HAProxy, MariaDB and PostgreSQL.
# Usage: run_tri_service_autonomous_loop.sh <ssh-host>
# Reboots the host. Run only against a disposable test VM with the three
# services installed (see test_tri_service_reboot.sh for the expected paths).
set -euo pipefail

HOST="${1:?usage: $0 <ssh-host>}"
REPO_DIR="$(cd "$(dirname "$(readlink -f "$0")")/../.." && pwd)"

echo "======================================================================"
echo "    ulp-driver: tri-service reboot persistence test"
echo "======================================================================"

# 1. Sync driver source to $HOST
echo ">>> Step 1: Syncing codebase to $HOST..."
ssh "$HOST" 'mkdir -p /root/ulp-driver'
scp -r "$REPO_DIR/ulp-driver" "$HOST:/root/ulp-driver/"
scp "$REPO_DIR/scripts/dev-vm/test_tri_service_reboot.sh" "$HOST:/root/test_tri_service_reboot.sh"

# 2. Build and install on $HOST
echo ">>> Step 2: Compiling driver and tools on $HOST..."
ssh "$HOST" '
cd /root/ulp-driver/ulp-driver
make clean && make
mkdir -p /lib/modules/$(uname -r)/extra
cp ulp_driver.ko /lib/modules/$(uname -r)/extra/ulp_driver.ko
depmod -a
echo "ulp_driver" > /etc/modules-load.d/ulp.conf
cp ulp_ctl /usr/local/bin/ulp_ctl
cp ulp_persist /usr/local/bin/ulp_persist
chmod +x /root/test_tri_service_reboot.sh
'

# 3. Run Pre-Reboot Setup & Verification
echo ">>> Step 3: Executing Pre-Reboot Baseline on $HOST..."
ssh "$HOST" '/root/test_tri_service_reboot.sh'

# 4. Trigger Reboot and Measure Boot Time
echo ">>> Step 4: Triggering guest VM reboot..."
ssh "$HOST" 'reboot' || true

START_TIME=$(date +%s)
echo "Reboot initiated at $(date). Polling SSH connectivity..."
BOOT_SUCCESS=0

for i in {1..35}; do
    ELAPSED=$(( $(date +%s) - START_TIME ))
    if ssh -o ConnectTimeout=1 -o BatchMode=yes "$HOST" 'uptime' 2>/dev/null; then
        echo -e "\n>>> $HOST is back after ${ELAPSED} seconds"
        BOOT_SUCCESS=1
        break
    fi
    echo -n "[${ELAPSED}s] ."
    sleep 1
done

if [ "$BOOT_SUCCESS" -ne 1 ]; then
    echo "ERROR: VM failed to boot within timeout!"
    exit 1
fi

# 5. Post-Reboot Verification & Memory Machine Code Inspection
echo ">>> Step 5: Performing Post-Reboot Livepatch & Memory Inspection..."
ssh "$HOST" '
echo "--- 1. SYSTEM STATUS & UPTIME ---"
uptime
lsmod | grep ulp_driver

echo -e "\n--- 2. EARLY-BOOT SERVICE STATUS (ulp-rules.service) ---"
systemctl status ulp-rules.service --no-pager || true

echo -e "\n--- 3. ACTIVE IN-KERNEL RULES TABLE ---"
/usr/local/bin/ulp_ctl list-rules > /root/post_reboot_rules.txt
cat /root/post_reboot_rules.txt

echo -e "\n--- 4. POST-REBOOT ACTIVE LIVEPATCHES (/proc/ulp_patches) ---"
cat /proc/ulp_patches > /root/post_reboot_patches.txt
cat /root/post_reboot_patches.txt

echo -e "\n--- 5. POST-REBOOT PROCESS MEMORY INSPECTION (/proc/\$PID/mem) ---"
python3 -c '\''
import os, sys

services = [("haproxy", "get_check_status_info"), ("mariadbd", "server_mysql_get_server_version"), ("postgres", "pg_backend_pid")]

for comm_name, func_name in services:
    found = False
    for pid in sorted([int(p) for p in os.listdir("/proc") if p.isdigit()]):
        try:
            with open(f"/proc/{pid}/comm") as f:
                if comm_name in f.read():
                    with open("/proc/ulp_patches") as pf:
                        for line in pf:
                            parts = line.split()
                            if len(parts) >= 6 and str(pid) == parts[0] and func_name in line:
                                vaddr = int(parts[5], 16)
                                with open(f"/proc/{pid}/mem", "rb", buffering=0) as mf:
                                    mf.seek(vaddr)
                                    raw = mf.read(16)
                                    hex_str = " ".join(f"{b:02x}" for b in raw)
                                    out = f"[+] PID {pid:5d} ({comm_name:8s}) at 0x{vaddr:016x}: {hex_str}"
                                    print(out)
                                    with open(f"/root/post_{comm_name}_mem.txt", "w") as of:
                                        of.write(out + "\n")
                                    found = True
                                    break
        except Exception:
            pass
        if found:
            break
'\''

echo -e "\n--- 6. POST-REBOOT SERVICE TRAFFIC TEST ---"
echo -n "HAProxy HTTP: " && curl -s http://localhost:8080/
echo -n "MariaDB Query: " && mariadb -e "SELECT @@version, 99999 AS post_reboot_test;"
echo -n "Postgres Query: " && su - postgres -c "psql -t -c '\''SELECT version(), 88888;'\''"

echo -e "\n--- 7. PRE-REBOOT vs POST-REBOOT MEMORY BYTE COMPARISON ---"
echo "HAProxy Pre-Reboot Memory:  $(cat /root/pre_haproxy_mem.txt 2>/dev/null || echo N/A)"
echo "HAProxy Post-Reboot Memory: $(cat /root/post_haproxy_mem.txt 2>/dev/null || echo N/A)"
echo "MariaDB Pre-Reboot Memory:  $(cat /root/pre_mariadbd_mem.txt 2>/dev/null || echo N/A)"
echo "MariaDB Post-Reboot Memory: $(cat /root/post_mariadbd_mem.txt 2>/dev/null || echo N/A)"
echo "Postgres Pre-Reboot Memory: $(cat /root/pre_postgres_mem.txt 2>/dev/null || echo N/A)"
echo "Postgres Post-Reboot Memory:$(cat /root/post_postgres_mem.txt 2>/dev/null || echo N/A)"

echo -e "\n--- 8. KERNEL BOOT DMESG LOGS ---"
dmesg | grep -E "ulp_driver|Kernel execve auto-patch"
'

echo "======================================================================"
echo ">>> Tri-service reboot test finished; compare the pre/post output above <<<"
echo "======================================================================"
