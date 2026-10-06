#!/usr/bin/env python3
"""
ulp-driver: Prometheus Metrics Exporter for Userspace Livepatching Subsystem
Exposes metrics on port 9142 (/metrics) for Prometheus / Grafana observability.
"""

import os
import sys
import time
import re
from http.server import HTTPServer, BaseHTTPRequestHandler

PORT = int(os.environ.get("ULP_EXPORTER_PORT", 9142))

def get_ulp_scope():
    try:
        with open("/proc/sys/kernel/ulp_scope", "r") as f:
            return int(f.read().strip())
    except Exception:
        return -1

def get_ulp_patches():
    patches = []
    try:
        with open("/proc/ulp_patches", "r") as f:
            lines = f.readlines()
            if len(lines) >= 3:
                for line in lines[2:]:
                    parts = line.split()
                    if len(parts) >= 8:
                        patches.append({
                            "pid": parts[0],
                            "uid": parts[1],
                            "comm": parts[2],
                            "patch_name": parts[3],
                            "func_name": parts[4],
                            "orig_addr": parts[5],
                            "patch_addr": parts[6],
                            "active": 1 if "ACTIVE" in parts[7] else 0
                        })
    except Exception:
        pass
    return patches

class MetricsHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path != "/metrics":
            self.send_response(404)
            self.end_headers()
            return

        scope = get_ulp_scope()
        patches = get_ulp_patches()
        active_count = sum(1 for p in patches if p["active"] == 1)

        output = []
        output.append("# HELP ulp_driver_loaded Whether the ULP kernel driver is loaded (1) or not (0)")
        output.append("# TYPE ulp_driver_loaded gauge")
        output.append(f"ulp_driver_loaded {1 if os.path.exists('/dev/ulp') else 0}")

        output.append("# HELP ulp_scope_mode Current sysctl kernel.ulp_scope mode (0=Disabled, 1=Same-UID, 2=Root-Only, 3=Locked)")
        output.append("# TYPE ulp_scope_mode gauge")
        output.append(f"ulp_scope_mode {scope}")

        output.append("# HELP ulp_active_patches_total Total number of active userspace livepatches")
        output.append("# TYPE ulp_active_patches_total gauge")
        output.append(f"ulp_active_patches_total {active_count}")

        output.append("# HELP ulp_patch_status Status of specific livepatches (1=Active, 0=Disabled)")
        output.append("# TYPE ulp_patch_status gauge")
        for p in patches:
            output.append(f'ulp_patch_status{{pid="{p["pid"]}",uid="{p["uid"]}",comm="{p["comm"]}",patch="{p["patch_name"]}",func="{p["func_name"]}"}} {p["active"]}')

        response_bytes = "\n".join(output).encode("utf-8") + b"\n"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
        self.send_header("Content-Length", str(len(response_bytes)))
        self.end_headers()
        self.wfile.write(response_bytes)

    def log_message(self, format, *args):
        pass

def main():
    print(f"Starting ulp-driver Prometheus Exporter on port {PORT}...")
    server = HTTPServer(("0.0.0.0", PORT), MetricsHandler)
    server.serve_forever()

if __name__ == "__main__":
    main()
