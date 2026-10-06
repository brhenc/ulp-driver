#!/usr/bin/env bash
# ==============================================================================
# Apply FRR Livepatch via /dev/ulp Kernel Module Driver (Debian & Fedora)
# ==============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BGPD_PID=$(pgrep -x bgpd || true)
if [ -z "$BGPD_PID" ]; then
    echo "Error: bgpd is not running"
    exit 1
fi

MODULE_DIR="/usr/lib64/frr/modules"
if [ ! -d "$MODULE_DIR" ]; then
    MODULE_DIR="/usr/lib/x86_64-linux-gnu/frr/modules"
    mkdir -p "$MODULE_DIR"
fi

MODULE_PATH="$MODULE_DIR/patch_bgp.so"
install -m 755 "$SCRIPT_DIR/patch_bgp.so" "$MODULE_PATH"
chown -R frr:frr "$MODULE_PATH" 2>/dev/null || true
restorecon -v "$MODULE_PATH" 2>/dev/null || true

echo "Targeting live bgpd PID: $BGPD_PID"

# 1. Fast sub-millisecond module injection (No GDB freeze)
if [ -x "/usr/local/bin/ulp_inject" ]; then
    /usr/local/bin/ulp_inject "$BGPD_PID" "$MODULE_PATH"
elif [ -x "$SCRIPT_DIR/../ulp-driver/ulp_inject" ]; then
    "$SCRIPT_DIR/../ulp-driver/ulp_inject" "$BGPD_PID" "$MODULE_PATH"
else
    gdb -q -batch \
      -ex "set debuginfod enabled off" \
      -ex "attach $BGPD_PID" \
      -ex "set \$handle = (void*)dlopen(\"$MODULE_PATH\", 2)" \
      -ex "detach" \
      -ex "quit" >/dev/null 2>&1 || true
fi

# 2. Calculate addresses using /proc/$PID/maps and ELF symbol tables
BGPD_EXE=$(readlink -f /proc/"$BGPD_PID"/exe)
BGPD_BASE=$(grep "$BGPD_EXE" /proc/"$BGPD_PID"/maps | head -n 1 | awk '{print $1}' | cut -d- -f1)
BGPD_OFFSET=$(nm -D "$BGPD_EXE" | grep -w "bgp_show_summary_vty" | awk '{print $1}')
ORIG_ADDR=$(python3 -c "print(hex(0x${BGPD_BASE} + 0x${BGPD_OFFSET}))")

PATCH_BASE=$(grep "patch_bgp.so" /proc/"$BGPD_PID"/maps | head -n 1 | awk '{print $1}' | cut -d- -f1)
PATCH_OFFSET=$(nm -D "$MODULE_PATH" | grep -w "livepatch_bgp_show_summary_vty" | awk '{print $1}')
NEW_ADDR=$(python3 -c "print(hex(0x${PATCH_BASE} + 0x${PATCH_OFFSET}))")

echo "[ULP] Target Function (bgp_show_summary_vty): $ORIG_ADDR"
echo "[ULP] Livepatch Hook  (livepatch_bgp...):      $NEW_ADDR"

# 3. Trigger Kernel Driver to apply 16-byte atomic trampoline
if [ -x "/usr/local/bin/ulp_ctl" ]; then
    /usr/local/bin/ulp_ctl apply "$BGPD_PID" "frr_shadow_variable" "bgp_show_summary_vty" "$ORIG_ADDR" "$NEW_ADDR" 64
else
    "$SCRIPT_DIR/../ulp-driver/ulp_ctl" apply "$BGPD_PID" "frr_shadow_variable" "bgp_show_summary_vty" "$ORIG_ADDR" "$NEW_ADDR" 64
fi

echo "=== Kernel livepatch applied successfully via /dev/ulp! ==="
