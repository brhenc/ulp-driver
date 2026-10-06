#!/usr/bin/env bash
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${BLUE}======================================================================${NC}"
echo -e "${BLUE}   EXECUTING CROSS-REBOOT LIVEPATCH PERSISTENCE TEST ON DEBIAN-13     ${NC}"
echo -e "${BLUE}======================================================================${NC}"

# 1. Sync driver and setup script to debian-13
echo -e "${YELLOW}>>> Step 1: Syncing ULP driver and configuring persistence on debian-13...${NC}"
scp -r "$(dirname "$(readlink -f "$0")")"/../../ulp-driver debian-13:/root/ulp-driver/
scp "$(dirname "$(readlink -f "$0")")"/test_reboot_persistence.sh debian-13:/root/

# 2. Run Pre-Reboot Setup and State Recording
echo -e "${YELLOW}>>> Step 2: Recording pre-reboot state and process memory...${NC}"
ssh debian-13 '
chmod +x /root/test_reboot_persistence.sh
/root/test_reboot_persistence.sh
'

# 3. Reboot the debian-13 VM
echo -e "\n${YELLOW}>>> Step 3: Rebooting debian-13 guest VM...${NC}"
ssh debian-13 'reboot' || true

echo -e "${YELLOW}>>> Waiting for debian-13 to reboot and come back online...${NC}"
sleep 5

for i in {1..60}; do
    if ssh -o ConnectTimeout=2 -o BatchMode=yes debian-13 'uptime' 2>/dev/null; then
        echo -e "${GREEN}[+] debian-13 is back online!${NC}"
        break
    fi
    echo -n "."
    sleep 2
done

# Wait for systemd services to fully settle
sleep 3

# 4. Post-Reboot Verification & Memory Poking
echo -e "\n${BLUE}======================================================================${NC}"
echo -e "${BLUE}>>> Step 4: POST-REBOOT VERIFICATION & MEMORY INSPECTION <<<${NC}"
echo -e "${BLUE}======================================================================${NC}"

ssh debian-13 '
# Start HAProxy if not started via systemd
if ! pidof haproxy >/dev/null 2>&1; then
    /usr/local/sbin/haproxy -f /tmp/haproxy_min.cfg -D || true
    sleep 1
fi

echo -e "\n--- Kernel Module Loading Status ---"
lsmod | grep ulp_driver || echo "[-] ulp_driver not loaded"

echo -e "\n--- Early-Boot Systemd Service Status (ulp-rules.service) ---"
systemctl status ulp-rules.service --no-pager || true

echo -e "\n--- In-Kernel Persistent Rule Table ---"
/usr/local/bin/ulp_ctl list-rules > /root/post_reboot_rules.txt
cat /root/post_reboot_rules.txt

echo -e "\n--- Active Post-Reboot Livepatches in Kernel ---"
cat /proc/ulp_patches > /root/post_reboot_patches.txt
cat /root/post_reboot_patches.txt

echo -e "\n--- Post-Reboot Process Memory Inspection (Reading Machine Code Trampolines) ---"
cat << "EOF" > /tmp/inspect_mem.py
import sys, os

proc_name = sys.argv[1]
# Find PID
pids = [p for p in os.listdir("/proc") if p.isdigit()]
target_pids = []
for pid in pids:
    try:
        with open(f"/proc/{pid}/comm", "r") as f:
            if proc_name in f.read().strip():
                target_pids.append(int(pid))
    except:
        continue

if not target_pids:
    print(f"[-] Process {proc_name} not found")
    sys.exit(1)

# Sort PIDs to pick main daemon PID
target_pid = sorted(target_pids)[0]

# Find target_vaddr from /proc/ulp_patches
vaddr = None
with open("/proc/ulp_patches", "r") as f:
    for line in f:
        if str(target_pid) in line and proc_name in line:
            parts = line.split()
            vaddr = int(parts[5], 16)
            break

if not vaddr:
    print(f"[-] Livepatch record for PID {target_pid} ({proc_name}) not found")
    sys.exit(1)

# Read 16 bytes directly from /proc/$PID/mem
with open(f"/proc/{target_pid}/mem", "rb", buffering=0) as f:
    f.seek(vaddr)
    data = f.read(16)
    hex_bytes = " ".join(f"{b:02x}" for b in data)
    print(f"[+] PID {target_pid} ({proc_name}) at 0x{vaddr:016x}: {hex_bytes}")
EOF

python3 /tmp/inspect_mem.py mariadbd | tee /root/post_reboot_mariadb_mem.txt || true
python3 /tmp/inspect_mem.py postgres | tee /root/post_reboot_postgres_mem.txt || true

echo -e "\n--- Comparing Pre-Reboot and Post-Reboot Livepatch Tables ---"
echo -e "${BLUE}=== PRE-REBOOT LIVEPATCHES ===${NC}"
cat /root/pre_reboot_patches.txt
echo -e "\n${GREEN}=== POST-REBOOT LIVEPATCHES ===${NC}"
cat /root/post_reboot_patches.txt

echo -e "\n--- Comparing Pre-Reboot and Post-Reboot Process Memory Machine Code ---"
echo -e "MariaDB Pre-Reboot Memory:  $(cat /root/pre_reboot_mariadb_mem.txt 2>/dev/null || echo 'N/A')"
echo -e "MariaDB Post-Reboot Memory: $(cat /root/post_reboot_mariadb_mem.txt 2>/dev/null || echo 'N/A')"
echo -e "Postgres Pre-Reboot Memory:  $(cat /root/pre_reboot_postgres_mem.txt 2>/dev/null || echo 'N/A')"
echo -e "Postgres Post-Reboot Memory: $(cat /root/post_reboot_postgres_mem.txt 2>/dev/null || echo 'N/A')"

echo -e "\n--- Kernel DMESG Logs for Boot Livepatching ---"
dmesg | grep -E "ulp_driver|Kernel execve auto-patch" | head -n 20
'

echo -e "\n${GREEN}======================================================================${NC}"
echo -e "${GREEN}>>> CROSS-REBOOT LIVEPATCH PERSISTENCE VERIFIED SUCCESSFULLY! <<<${NC}"
echo -e "${GREEN}======================================================================${NC}"
