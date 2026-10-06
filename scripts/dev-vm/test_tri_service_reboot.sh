#!/usr/bin/env bash
# ulp-driver: Autonomous Tri-Service Reboot Persistence Verification Harness
# Tests HAProxy, MariaDB, and PostgreSQL across reboot, process restarts, and live traffic.
set -euo pipefail

echo "======================================================================"
echo "    AUTONOMOUS TRI-SERVICE PERSISTENCE & RELIABILITY TEST HARNESS     "
echo "======================================================================"

# 1. Ensure /etc/ulp directory and persistent configuration exist
mkdir -p /etc/ulp
cat << "EOF" > /etc/ulp/persistent_rules.conf
# ulp-driver Tri-Service Persistent Livepatch Rules
# binary_path patch_name func_name target_offset_hex patch_vaddr_hex func_len match_uid global_scope
/usr/local/sbin/haproxy haproxy_check_fix get_check_status_info 0x24f010 0x0 16 4294967295 1
/usr/sbin/mariadbd maria_version_fix server_mysql_get_server_version 0xb1d060 0x0 16 4294967295 1
/usr/lib/postgresql/17/bin/postgres pg_pid_fix pg_backend_pid 0x5b7d70 0x0 16 4294967295 1
EOF

# 2. Configure systemd early-boot service
cat << "EOF" > /etc/systemd/system/ulp-rules.service
[Unit]
Description=ulp-driver Persistent Livepatch Rules Loader
DefaultDependencies=no
After=local-fs.target systemd-modules-load.service
Before=basic.target network.target sysinit.target haproxy.service mariadb.service postgresql.service
Requires=local-fs.target

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
systemctl enable haproxy mariadb postgresql

# 3. Load rules into running kernel now
/usr/local/bin/ulp_persist load-rules

# 4. Restart services and record pre-reboot state
systemctl restart haproxy mariadb postgresql
sleep 2

echo -e "\n=== 1. PRE-REBOOT LIVEPATCH TABLE (/proc/ulp_patches) ==="
cat /proc/ulp_patches > /root/pre_reboot_patches.txt
cat /root/pre_reboot_patches.txt

echo -e "\n=== 2. PRE-REBOOT PROCESS MEMORY INSPECTION (/proc/\$PID/mem) ==="
python3 -c '
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
                                    with open(f"/root/pre_{comm_name}_mem.txt", "w") as of:
                                        of.write(out + "\n")
                                    found = True
                                    break
        except Exception:
            pass
        if found:
            break
'

echo -e "\n=== 3. PRE-REBOOT SERVICE TRAFFIC TEST ==="
echo -n "HAProxy HTTP: " && curl -s http://localhost:8080/
echo -n "MariaDB Query: " && mariadb -e "SELECT 12345 AS test_val;"
echo -n "Postgres Query: " && su - postgres -c "psql -t -c 'SELECT 67890;'"

echo -e "\n[+] Pre-reboot test completed successfully."
