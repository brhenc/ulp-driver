# Operator Tooling, TUI Dashboard & Continuous Automation

**Module:** Operator Tools & Interfaces  
**Paths:** `tools/ulp_tui.py`, `tools/ulp_crypto_verifier.py`, `tests/test_multi_version_continuous_suite.py`  
**Path:** `docs/hacking/06_OPERATOR_TOOLING_TUI_AND_AUTOMATION.md`  

---

## 1. The ULP Operator Terminal UI (`tools/ulp_tui.py`)

The Terminal UI is a curses dashboard that connects directly to `/dev/ulp` via the Plan 9 VFS protocol:

```
┌────────────────────────────────────────────────────────────────────────┐
│  PROJECT ULP_DRIVER: ENTERPRISE ULP DASHBOARD v3.0                 │
│  Kernel Driver: ARMED (TTL: 42s) | Mode: 0600 VFS Stream | Ring: OK    │
├────────────────────────────────────────────────────────────────────────┤
│  TARGET DAEMONS (Use [UP]/[DOWN] or [TAB] to Select):                  │
│                                                                        │
│  ► [1] pgrust (Rust 1.85)     | PID: 23486 | VADDR: 0x56253e3cbbe0     │
│        Current: V2: Shadow Metrics (Lockless 0x2001) (+2000)           │
│    [2] MariaDB 11.8 (C++)     | PID: 20646 | VADDR: 0x564eae75a000     │
│        Current: V0 (Baseline Restored)                                 │
│    [3] server_go (Golang)     | PID: 23517 | VADDR: 0x00000062cf40     │
│        Current: V3: Production Async (v3.0.0-PRODUCTION)               │
│    [4] PostgreSQL 17 (C)      | PID: 23507 | VADDR: 0x55d8f102c000     │
│        Current: V0 (Baseline)                                          │
│    [5] HAProxy 3.0 (C)        | PID: 23511 | VADDR: 0x5590c2104000     │
│        Current: V1: Sample Commit                                      │
├────────────────────────────────────────────────────────────────────────┤
│  AVAILABLE GENERATIONS FOR SELECTED TARGET:                            │
│  [1] Deploy V1 (CVE Hotfix & Audit)                                    │
│  [2] Deploy V2 (Shadow Metrics & RCU)                                  │
│  [3] Deploy V3 (AVX2 SIMD / Async Production)                          │
│  [R] Atomically Revert to V0 (Baseline)                                │
├────────────────────────────────────────────────────────────────────────┤
│  LIVE TELEMETRY LOG (/dev/ulp Event Ring Buffer):                      │
│  14:34:12 [ARMED] Driver armed by UID 0 for 60s window                 │
│  14:34:15 [APPLY] PID 23517 patched 'main.GetServiceStatus' -> Gen 3   │
│  14:34:20 [REVERT] PID 23486 reverted 'pgrust_get_version' -> V0       │
├────────────────────────────────────────────────────────────────────────┤
│  [A] ARM Driver  [D] Disarm  [1/2/3] Deploy  [R] Revert  [Q] Quit      │
└────────────────────────────────────────────────────────────────────────┘
```

### 1.1 Running the TUI
```bash
# Must be executed as root on host or VM
python3 tools/ulp_tui.py
```

### 1.2 Target Auto-Detection & Process Resolution
The TUI automatically monitors process tables:
* `pgrust`: `pgrep -f pgrust_daemon`
* `server_go`: `pgrep -f server_go` (resolves `.gopclntab` or static ELF addresses)
* `mariadbd`: `pgrep -x mariadbd`
* `postgres`: Resolves active backend worker PID via `psql -t -A -c "SELECT pg_backend_pid();"`
* `haproxy`: `pgrep -f 'haproxy -W' | tail -n 1`

---

## 2. Cryptographic Patch Verification (`tools/ulp_crypto_verifier.py`)

Before any livepatch is submitted to `/dev/ulp`, the operator tooling verifies cryptographic authenticity:

```
Patch Binary / DSO (.so / .bin)
             │
             ├──► [ Cosign Verification ] ──► Validates ECDSA-P256 Key Pair
             ├──► [ GPG Verification ]    ──► Validates OpenPGP RSA-3072 Keyring
             └──► [ Rekor Transparency ]  ──► Validates Immutable Audit Log
```

### 2.1 Verification CLI Usage:
```bash
python3 tools/ulp_crypto_verifier.py verify \
    --patch /root/ulp-driver/haproxy-multi-patch/patch_sample.so \
    --cosign-key /root/ulp-driver/ulp-keys/haproxy-cosign.pub
```

---

## 3. Continuous Verification Harness (`tests/test_multi_version_continuous_suite.py`)

The automated regression suite tests the complete $V_0 \to V_1 \to V_2 \to V_3 \to \text{Resumption} \to V_0$ lifecycle across all running daemons simultaneously under active traffic load:

```bash
python3 tests/test_multi_version_continuous_suite.py
```

### 5 Validation Stages Executed:
1. **Stage 1**: Baseline $V_0$ state validation across all daemons.
2. **Stage 2**: $V_1$ Generation deployment (Security hotfixes).
3. **Stage 3**: $V_2$ Generation deployment (Shadow telemetry).
4. **Stage 4**: $V_3$ Generation deployment (SIMD query acceleration).
5. **Stage 5**: Kernel persistence & atomic $V_0$ rollback verification under sustained traffic.
