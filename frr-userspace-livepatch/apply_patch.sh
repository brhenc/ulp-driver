#!/bin/bash
set -euo pipefail

BGPD_PID=$(pgrep -x bgpd || true)
if [ -z "$BGPD_PID" ]; then
    echo "Error: bgpd is not running"
    exit 1
fi

MODULE_PATH="/usr/lib64/frr/modules/patch_bgp.so"
echo "Targeting live bgpd PID: $BGPD_PID with module $MODULE_PATH"

# 1. Use gdb batch mode to load the shared library and apply the trampoline atomically
gdb -batch \
  -ex "set debuginfod enabled off" \
  -ex "attach $BGPD_PID" \
  -ex "set \$handle = (void*)dlopen(\"$MODULE_PATH\", 2)" \
  -ex "set \$new_func = (void*)dlsym(\$handle, \"livepatch_bgp_show_summary_vty\")" \
  -ex "set \$orig_func = (void*)bgp_show_summary_vty" \
  -ex "printf \"[LIVEPATCH] dlopen handle: %p, orig_func: %p, new_func: %p\n\", \$handle, \$orig_func, \$new_func" \
  -ex "set *(void**)dlsym(\$handle, \"orig_bgp_show_summary\") = \$orig_func" \
  -ex "call (int)mprotect(((uintptr_t)\$orig_func & ~0xFFFULL), 4096, 7)" \
  -ex "set *(unsigned char*)((uintptr_t)\$orig_func + 0) = 0xf3" \
  -ex "set *(unsigned char*)((uintptr_t)\$orig_func + 1) = 0x0f" \
  -ex "set *(unsigned char*)((uintptr_t)\$orig_func + 2) = 0x1e" \
  -ex "set *(unsigned char*)((uintptr_t)\$orig_func + 3) = 0xfa" \
  -ex "set *(unsigned char*)((uintptr_t)\$orig_func + 4) = 0x48" \
  -ex "set *(unsigned char*)((uintptr_t)\$orig_func + 5) = 0xb8" \
  -ex "set *(unsigned long*)((uintptr_t)\$orig_func + 6) = (unsigned long)\$new_func" \
  -ex "set *(unsigned char*)((uintptr_t)\$orig_func + 14) = 0xff" \
  -ex "set *(unsigned char*)((uintptr_t)\$orig_func + 15) = 0xe0" \
  -ex "call (int)mprotect(((uintptr_t)\$orig_func & ~0xFFFULL), 4096, 5)" \
  -ex "detach" \
  -ex "quit"

echo "=== Patch successfully applied to running bgpd (PID $BGPD_PID) ==="
