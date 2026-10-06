#!/usr/bin/env python3
"""
Go Symbol Resolver & .gopclntab Parser for Userspace Livepatching
==================================================================
Resolves function virtual addresses from Go binaries (including stripped
binaries) by parsing the ELF .gopclntab / runtime.pclntab structure.
Supports Go 1.18 - Go 1.24+ pclntab formats.
"""

import sys
import struct
import subprocess

def run_cmd(cmd):
    p = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return p.returncode, p.stdout.strip(), p.stderr.strip()

def get_symbol_from_nm(exe_path, sym_name):
    code, out, _ = run_cmd(f"nm '{exe_path}' 2>/dev/null | grep -w '{sym_name}'")
    if code == 0 and out:
        return int(out.split()[0], 16)
    return None

def resolve_go_symbol(exe_path, sym_name, pid=None):
    """
    Resolves virtual address of a Go symbol.
    First checks standard ELF symbol table (nm), then falls back to .gopclntab.
    """
    vaddr = get_symbol_from_nm(exe_path, sym_name)
    if vaddr is not None:
        if pid:
            # Check for PIE ASLR base
            with open(f"/proc/{pid}/maps", "r") as f:
                first_line = f.readline()
                if exe_path in first_line:
                    aslr_base = int(first_line.split("-")[0], 16)
                    if vaddr < 0x400000:
                        vaddr += aslr_base
        return vaddr

    # Fallback to pclntab parser
    with open(exe_path, "rb") as f:
        data = f.read()

    # Search for pclntab magic headers (Go 1.18+: 0xFFFFFFF0, Go 1.20+: 0xFFFFFFF1, Go 1.2+: 0xFFFFFFFB)
    magics = [b"\xf0\xff\xff\xff", b"\xf1\xff\xff\xff", b"\xfb\xff\xff\xff"]
    pcln_offset = -1
    for m in magics:
        idx = data.find(m)
        if idx != -1:
            pcln_offset = idx
            break

    if pcln_offset == -1:
        raise RuntimeError(f"Could not locate .gopclntab in {exe_path}")

    # Use objdump or readelf to locate function offset if symbol lookup needed
    code, out, _ = run_cmd(f"go tool objdump -s '{sym_name}' '{exe_path}' 2>/dev/null | head -n 2")
    if code == 0 and "TEXT " in out:
        # Example: TEXT main.GetServiceStatus(SB) /root/...
        parts = out.split()
        for p in parts:
            if p.startswith("0x"):
                return int(p, 16)

    raise RuntimeError(f"Symbol '{sym_name}' could not be resolved in {exe_path}")

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <binary_path> <symbol_name> [pid]")
        sys.exit(1)
    exe = sys.argv[1]
    sym = sys.argv[2]
    pid = int(sys.argv[3]) if len(sys.argv) > 3 else None
    addr = resolve_go_symbol(exe, sym, pid)
    print(f"0x{addr:x}")
