#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HAP_PID=$(pidof haproxy | awk '{print $1}' || true)
if [ -z "$HAP_PID" ]; then
    echo "Error: haproxy is not running"
    exit 1
fi

MODULE_DIR="/var/run/haproxy/modules"
mkdir -p "$MODULE_DIR"
MODULE_PATH="$MODULE_DIR/patch_haproxy.so"
install -m 755 "$SCRIPT_DIR/patch_haproxy.so" "$MODULE_PATH"

echo "=== Targeting live HAProxy PID: $HAP_PID ==="

# 1. Fast sub-millisecond module injection (No GDB freeze)
if [ -x "/usr/local/bin/ulp_inject" ]; then
    /usr/local/bin/ulp_inject "$HAP_PID" "$MODULE_PATH"
elif [ -x "$SCRIPT_DIR/../ulp-driver/ulp_inject" ]; then
    "$SCRIPT_DIR/../ulp-driver/ulp_inject" "$HAP_PID" "$MODULE_PATH"
else
    gdb -q -batch \
      -ex "set debuginfod enabled off" \
      -ex "attach $HAP_PID" \
      -ex "set \$handle = (void*)dlopen(\"$MODULE_PATH\", 2)" \
      -ex "detach" \
      -ex "quit" >/dev/null 2>&1 || true
fi

# 2. Calculate addresses using /proc/$PID/maps and ELF symbol tables
HAP_EXE=$(readlink -f /proc/"$HAP_PID"/exe)
HAP_BASE=$(grep "$HAP_EXE" /proc/"$HAP_PID"/maps | head -n 1 | awk '{print $1}' | cut -d- -f1)

# Function 1: stktable_deinit
STK_OFF=$(nm "$HAP_EXE" | grep -w "stktable_deinit" | awk '{print $1}')
STK_ORIG=$(python3 -c "print(hex(0x${HAP_BASE} + 0x${STK_OFF}))")

PATCH_BASE=$(grep "patch_haproxy.so" /proc/"$HAP_PID"/maps | head -n 1 | awk '{print $1}' | cut -d- -f1)
STK_PATCH_OFF=$(nm -D "$MODULE_PATH" | grep -w "livepatch_stktable_deinit" | awk '{print $1}')
STK_NEW=$(python3 -c "print(hex(0x${PATCH_BASE} + 0x${STK_PATCH_OFF}))")

echo "[ULP-HAPROXY] Patching stktable_deinit: $STK_ORIG -> $STK_NEW"
ulp_ctl apply "$HAP_PID" "haproxy_sanitizer_fixes" "stktable_deinit" "$STK_ORIG" "$STK_NEW" 128

# Function 2: deinit_proxy
PX_OFF=$(nm "$HAP_EXE" | grep -E " [Tt] deinit_proxy$" | awk '{print $1}')
PX_ORIG=$(python3 -c "print(hex(0x${HAP_BASE} + 0x${PX_OFF}))")

PX_PATCH_OFF=$(nm -D "$MODULE_PATH" | grep -w "livepatch_deinit_proxy" | awk '{print $1}')
PX_NEW=$(python3 -c "print(hex(0x${PATCH_BASE} + 0x${PX_PATCH_OFF}))")

echo "[ULP-HAPROXY] Patching deinit_proxy:    $PX_ORIG -> $PX_NEW"
ulp_ctl apply "$HAP_PID" "haproxy_sanitizer_fixes" "deinit_proxy" "$PX_ORIG" "$PX_NEW" 128

echo "=== HAProxy livepatch applied successfully via /dev/ulp! ==="
