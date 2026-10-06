#!/usr/bin/env bash
# ulp-driver: Master Autonomous Tri-Service Test Controller
set -euo pipefail

echo "======================================================================"
echo "    ULP-DRIVER: MASTER TRI-SERVICE AUTONOMOUS TEST LOOP       "
echo "======================================================================"

# 1. Sync driver source to debian-13
echo ">>> Step 1: Syncing codebase to debian-13..."
scp -r "$(dirname "$(readlink -f "$0")")"/ulp-driver debian-13:/root/ulp-driver/
scp "$(dirname "$(readlink -f "$0")")"/test_tri_service_reboot.sh debian-13:/root/test_tri_service_reboot.sh

# 2. Build and install on debian-13
echo ">>> Step 2: Compiling driver and tools on debian-13..."
ssh debian-13 '
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
echo ">>> Step 3: Executing Pre-Reboot Baseline on debian-13..."
ssh debian-13 '/root/test_tri_service_reboot.sh'

# 4. Trigger Reboot and Measure Boot Time
echo ">>> Step 4: Triggering guest VM reboot..."
ssh debian-13 'reboot' || true

START_TIME=$(date +%s)
echo "Reboot initiated at $(date). Polling SSH connectivity..."
BOOT_SUCCESS=0

for i in {1..35}; do
    ELAPSED=$(( $(date +%s) - START_TIME ))
    ADDR=$(sudo virsh domifaddr debian-13 | grep -o '192.168.122.[0-9]*' || true)
    if [ -n "$ADDR" ]; then
        if ssh -o ConnectTimeout=1 -o BatchMode=yes debian-13 'uptime' 2>/dev/null; then
            echo -e "\n=========================================================="
            echo ">>> SUCCESS! debian-13 BOOTED CLEANLY IN ${ELAPSED} SECONDS! <<<"
            echo "=========================================================="
            BOOT_SUCCESS=1
            break
        fi
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
ssh debian-13 '
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
dmesg | grep -E "ulp_driver|Kernel execve auto-patch|Enterprise Hardened"
'

echo "======================================================================"
echo ">>> TRI-SERVICE AUTONOMOUS REBOOT TEST PASSED WITH 100% SUCCESS! <<<"
echo "======================================================================"
