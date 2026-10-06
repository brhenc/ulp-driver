#!/usr/bin/env python3
import threading
import urllib.request
import subprocess
import sys

errors = []

def test_haproxy(n):
    for _ in range(n):
        try:
            with urllib.request.urlopen("http://localhost:8080/", timeout=3) as resp:
                if resp.status != 200:
                    errors.append(f"HAProxy status {resp.status}")
        except Exception as e:
            errors.append(f"HAProxy error: {e}")

def test_mariadb(n):
    for _ in range(n):
        try:
            res = subprocess.run(["mariadb", "-u", "root", "-sN", "-e", "SELECT 1+1;"],
                                 capture_output=True, text=True, timeout=3)
            if res.stdout.strip() != "2":
                errors.append(f"MariaDB wrong result: {res.stdout.strip()} (err: {res.stderr.strip()})")
        except Exception as e:
            errors.append(f"MariaDB error: {e}")

def test_postgres(n):
    for _ in range(n):
        try:
            res = subprocess.run(["psql", "-U", "postgres", "-h", "127.0.0.1", "-t", "-A", "-c", "SELECT 2+2;"],
                                 capture_output=True, text=True, timeout=3)
            if res.stdout.strip() != "4":
                errors.append(f"Postgres wrong result: {res.stdout.strip()} (err: {res.stderr.strip()})")
        except Exception as e:
            errors.append(f"Postgres error: {e}")

threads = []
for i in range(8):
    threads.append(threading.Thread(target=test_haproxy, args=(25,)))
    threads.append(threading.Thread(target=test_mariadb, args=(15,)))
    threads.append(threading.Thread(target=test_postgres, args=(15,)))

for t in threads:
    t.start()
for t in threads:
    t.join()

if errors:
    print(f"[-] Encountered {len(errors)} traffic errors. First 5 errors:")
    for err in errors[:5]:
        print(f"    - {err}")
    sys.exit(1)
else:
    print("[+] All 440 concurrent tri-service requests completed with 100% success!")
