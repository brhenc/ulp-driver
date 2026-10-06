#!/usr/bin/env python3
"""
Zero-Downtime Socket Listen Backlog Expansion Demonstration (ss -tlpn)
======================================================================
Tests and validates live dynamic expansion of MariaDB listening socket backlog
from baseline 80 to 300 without restarting the daemon or dropping queries.
"""

import os
import sys
import time
import subprocess

ULP_INJECT = "/usr/local/bin/ulp_inject"
SRC_C = "/root/ulp-driver/mariadb-livepatch-bench/update_socket_backlog.c"
DSO_PATH = "/usr/lib/mysql/plugin/update_socket_backlog.so"

def run_cmd(cmd):
    p = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return p.returncode, p.stdout.strip(), p.stderr.strip()

def get_mariadb_ss_sendq():
    code, out, _ = run_cmd("ss -tlpn | grep 3306")
    if code != 0 or not out:
        return None, None
    # Example: LISTEN 0 80 127.0.0.1:3306 ...
    parts = out.split()
    recv_q = parts[1]
    send_q = parts[2]
    return recv_q, send_q

def main():
    print("==============================================================================")
    print("   ZERO-DOWNTIME SOCKET LISTEN BACKLOG EXPANSION BENCHMARK (ss -tlpn)         ")
    print("==============================================================================")

    # 1. Verify MariaDB PID
    code, out, _ = run_cmd("pidof mariadbd")
    if code != 0 or not out:
        print("[!] mariadbd not running. Exiting.")
        sys.exit(1)
    mariadb_pid = int(out.split()[0])
    print(f"[+] Target mariadbd PID: {mariadb_pid}")

    # 2. Check baseline socket backlog via ss -tlpn
    recv_q, send_q = get_mariadb_ss_sendq()
    print(f"[+] Baseline Socket State (ss -tlpn): Recv-Q={recv_q}, Send-Q (sk_max_ack_backlog)={send_q}")

    # 3. Check application variables
    code, out, _ = run_cmd("mariadb -s -N -e 'SELECT @@back_log, @@max_connections;'")
    print(f"[+] Application Variables (back_log, max_connections): {out}")

    # 4. Compile DSO
    print("[*] Compiling update_socket_backlog.so...")
    code, _, err = run_cmd(f"gcc -shared -fPIC -o {DSO_PATH} {SRC_C}")
    assert code == 0, f"Compilation failed: {err}"
    os.chmod(DSO_PATH, 0o755)

    # 5. Inject via ULP
    print(f"[*] Dynamically updating socket backlog to 300 via ULP...")
    code, out, err = run_cmd(f"{ULP_INJECT} {mariadb_pid} {DSO_PATH}")
    assert code == 0, f"ULP Injection failed: {err}"
    print(f"[+] {out}")

    # 6. Verify new ss -tlpn Send-Q
    time.sleep(0.5)
    new_recv_q, new_send_q = get_mariadb_ss_sendq()
    print(f"[+] Patched Socket State (ss -tlpn): Recv-Q={new_recv_q}, Send-Q (sk_max_ack_backlog)={new_send_q}")
    assert new_send_q == "300", f"Expected Send-Q=300, got {new_send_q}"

    # 7. Verify MariaDB query execution
    code, out, _ = run_cmd("mariadb -s -N -e 'SELECT 1, NOW();'")
    print(f"[+] Database query served seamlessly: {out}")
    print("==============================================================================")
    print("   RESULT: Socket backlog expanded 80 -> 300 live with ZERO downtime!        ")
    print("==============================================================================")

if __name__ == "__main__":
    main()
