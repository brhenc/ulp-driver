#!/usr/bin/env bash
# ==============================================================================
# ulp-driver: Cross-Reboot Livepatch Persistence Verification Suite
# ==============================================================================
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${BLUE}======================================================================${NC}"
echo -e "${BLUE}   CROSS-REBOOT PERSISTENCE & PROCESS MEMORY INSPECTION SUITE         ${NC}"
echo -e "${BLUE}======================================================================${NC}"

# 1. Compile driver and tools
cd /root/ulp-driver/ulp-driver
make clean && make
gcc -O2 -Wall -o /usr/local/bin/ulp_ctl ulp_ctl.c
gcc -O2 -Wall -o /usr/local/bin/ulp_persist ulp_persist.c -lcrypto

# 2. Install Kernel Module for Autoloading
KVER=$(uname -r)
mkdir -p "/lib/modules/$KVER/extra"
cp ulp_driver.ko "/lib/modules/$KVER/extra/ulp_driver.ko"
depmod -a

echo "ulp_driver" > /etc/modules-load.d/ulp.conf

# 3. Create Persistent Rules Configuration
mkdir -p /etc/ulp
cat << "EOF" > /etc/ulp/persistent_rules.conf
# <binary_path> <patch_name> <func_name> <target_offset_hex> <patch_vaddr_hex> <func_len> <uid> <global_scope>
/usr/sbin/mariadbd maria_fix server_mysql_get_server_version 0xb1d060 0x0 16 4294967295 1
/usr/lib/postgresql/17/bin/postgres pg_fix pg_backend_pid 0x5b7d70 0x0 16 4294967295 1
EOF

# 4. Install and Enable Systemd Early-Boot Service
cat << "EOF" > /etc/systemd/system/ulp-rules.service
[Unit]
Description=ulp-driver Persistent Livepatch Rules Loader
DefaultDependencies=no
After=systemd-modules-load.service
Before=basic.target network.target sysinit.target mariadb.service postgresql.service

[Service]
Type=oneshot
ExecStartPre=-/sbin/modprobe ulp_driver
ExecStart=/usr/local/bin/ulp_persist load-rules
RemainAfterExit=yes

[Install]
WantedBy=basic.target
EOF

systemctl daemon-reload
systemctl enable ulp-rules.service
systemctl enable mariadb postgresql

# 5. Load driver and activate rules
rmmod ulp_driver 2>/dev/null || true
modprobe ulp_driver
/usr/local/bin/ulp_persist load-rules

# 6. Restart Daemons so Kernel Execve Hooks Apply Livepatches
echo -e "${YELLOW}>>> Restarting MariaDB and PostgreSQL...${NC}"
systemctl restart mariadb postgresql
sleep 2

# 7. Record PRE-REBOOT Livepatch State & Inspect Process Memory
echo -e "\n${BLUE}======================================================================${NC}"
echo -e "${BLUE}>>> RECORDING PRE-REBOOT STATE & PROCESS MEMORY <<<${NC}"
echo -e "${BLUE}======================================================================${NC}"

/usr/local/bin/ulp_ctl list-rules > /root/pre_reboot_rules.txt
cat /proc/ulp_patches > /root/pre_reboot_patches.txt

cat /root/pre_reboot_rules.txt
echo ""
cat /root/pre_reboot_patches.txt

# Python helper to inspect memory of target process at function address
cat << "EOF" > /tmp/inspect_mem.py
import sys, os

proc_name = sys.argv[1]
# Find PID
pids = [p for p in os.listdir('/proc') if p.isdigit()]
target_pid = None
for pid in pids:
    try:
        with open(f'/proc/{pid}/comm', 'r') as f:
            if proc_name in f.read().strip():
                target_pid = int(pid)
                break
    except:
        continue

if not target_pid:
    print(f"[-] Process {proc_name} not found")
    sys.exit(1)

# Find target_vaddr from /proc/ulp_patches
vaddr = None
with open('/proc/ulp_patches', 'r') as f:
    for line in f:
        if str(target_pid) in line and proc_name in line:
            parts = line.split()
            vaddr = int(parts[5], 16)
            break

if not vaddr:
    print(f"[-] Livepatch record for PID {target_pid} ({proc_name}) not found")
    sys.exit(1)

# Read 16 bytes directly from /proc/$PID/mem
with open(f'/proc/{target_pid}/mem', 'rb', buffering=0) as f:
    f.seek(vaddr)
    data = f.read(16)
    hex_bytes = ' '.join(f'{b:02x}' for b in data)
    print(f"[+] PID {target_pid} ({proc_name}) at 0x{vaddr:016x}: {hex_bytes}")
EOF

echo -e "\n${YELLOW}--- Inspecting Live Process Memory Bytes at Patch Addresses ---${NC}"
python3 /tmp/inspect_mem.py mariadbd | tee /root/pre_reboot_mariadb_mem.txt
python3 /tmp/inspect_mem.py postgres | tee /root/pre_reboot_postgres_mem.txt

echo -e "\n${GREEN}[+] Pre-reboot livepatch state and memory bytes recorded successfully.${NC}"
