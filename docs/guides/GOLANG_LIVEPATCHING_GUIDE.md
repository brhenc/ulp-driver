# Golang Userspace Livepatching Architecture & Guide

**Branch:** `golang-support`  
**Target:** Go 1.18 – Go 1.24+ (x86_64 `ABIInternal`)  
**Subsystems:** ULP Kernel Driver (`/dev/ulp`), `ulp_inject`, `.gopclntab` Symbol Resolver  

---

## 1. Executive Summary

Livepatching Golang daemons presents unique engineering challenges compared to traditional C or Rust binaries due to the **Go Runtime's M:N Goroutine Scheduler**, **Dynamic Segmented Stacks (`runtime.morestack`)**, and **`ABIInternal` Register Calling Convention**.

With the `golang-support` branch of ulp-driver, we implement native, zero-downtime userspace livepatching for both:
1. **Pure Statically Linked Go Binaries (`CGO_ENABLED=0`)**: Injected via remote `sys_mmap` code pages.
2. **Dynamic / CGO-Enabled Go Daemons (`CGO_ENABLED=1`)**: Injected via soft-realtime safe `dlopen` execution.

---

## 2. Deep Dive: Golang ABI & Runtime Mechanics

### 2.1 Calling Convention: `ABIInternal` vs System V ABI

Starting with Go 1.17, the Go compiler uses **`ABIInternal`** for register-based parameter passing on x86_64:

```
┌────────────────────────────────────────────────────────┐
│ Register | Role in Go ABIInternal                     │
├────────────────────────────────────────────────────────┤
│ RAX      | Return 0 / Argument 0 (Data pointer)        │
│ RBX      | Return 1 / Argument 1 (Length/Capacity)     │
│ RCX, RDI | Arguments 2, 3                              │
│ RSI, R8  | Arguments 4, 5                              │
│ R9, R10  | Arguments 6, 7                              │
│ R11      | Scratch / Trampoline Register (Safe to clobber) │
│ R14      | Current Goroutine Pointer (g = runtime.g)   │
│ R15      | Go Runtime Global / Scratch                 │
└────────────────────────────────────────────────────────┘
```

> [!IMPORTANT]
> In Go `ABIInternal`, register **`R11`** is explicitly designated as a **scratch register for cross-boundary calls and dynamic trampolines**. 
> This allows ULP's absolute jump trampolines (`movabs $target, %r11; jmpq *%r11`) or 5-byte relative jumps (`jmp <rel32>`) to execute without corrupting any arguments, return values, or the `g` pointer (`R14`).

---

### 2.2 Stack Split Checks & Goroutine Preamble

Unlike C/Rust functions with fixed stack frames, Go functions typically start with a stack boundary check:
```assembly
CMPQ SP, 16(R14)     # Compare RSP with g.stackguard0
JLS  morestack       # Jump to runtime.morestack_noctxt if stack growth required
```
ULP installs its entry trampoline directly at the first instruction (`0x00`), intercepting execution *before* the stack check. The patched function executes inside the existing goroutine stack frame without triggering unnecessary stack reallocations.

---

### 2.3 Stripped Binary Symbol Resolution via `.gopclntab`

Go binaries statically embed the **Program Counter Line Table (`.gopclntab`)**. Even if a binary is stripped using `go build -ldflags="-s -w"`, the symbol names and function entry points remain preserved inside `.gopclntab` for panic stack unwinding and GC stack maps.

[`go_sym_resolver.py`](/go-livepatch-bench/go_sym_resolver.py) parses `.gopclntab` magic headers (`0xFFFFFFF0` for Go 1.18+, `0xFFFFFFF1` for Go 1.20+) to extract function virtual addresses on stripped production daemons without debug symbols.

---

## 3. Comparison Matrix: C vs C++ vs Rust vs Golang

| Dimension | C (HAProxy, MariaDB) | C++ (MariaDB, Percona) | Rust (pgrust) | Golang (`server_go`) |
| :--- | :--- | :--- | :--- | :--- |
| **Calling Convention** | System V AMD64 ABI (RDI, RSI, RDX...) | System V AMD64 ABI (`this` in RDI) | Rust ABI / `extern "C"` | `ABIInternal` (RAX, RBX, RCX...) |
| **Symbol Resolution** | ELF `.symtab` / `.dynsym` | Mangled symbols (`_Z...`) via demangler | Mangled symbols (`_ZN...` / `_R...`) | `.gopclntab` / ELF symbol table |
| **Stack Model** | Fixed OS Thread Stack | Fixed OS Thread Stack | Fixed OS Thread Stack | Dynamic Segmented Goroutine Stacks |
| **Concurrency Model** | 1:1 Kernel Threads | 1:1 Kernel Threads | 1:1 Kernel Threads / Tokio | M:N Goroutine Scheduler (M, P, G) |
| **Preemption** | None (OS Preemption) | None (OS Preemption) | Cooperative / Async | Signal-Based (`SIGURG`) Preemption |
| **Livepatch Cost** | Baseline | **Zero Extra Cost** (Vtables & mangling resolved natively) | **Zero Extra Cost** (Atomic trampolines) | **Zero Extra Cost** (Safe via `R11` scratch) |

---

## 4. Multi-Version Continuous Livepatch Verification

Verified live on Debian 13 VM (`192.168.122.171`) via [`go-livepatch-bench/test_go_continuous_livepatch.py`](/go-livepatch-bench/test_go_continuous_livepatch.py):

```
==============================================================================
   GOLANG CONTINUOUS MULTI-VERSION LIVEPATCHING VERIFICATION SUITE            
==============================================================================
[*] Starting Go REST server on :9090...
[+] Go Server running with PID: 23327
[+] Baseline V0 Status: ORIGINAL_UNPATCHED_GO_SERVICE | Version: v1.0.0-GA

>>> [STAGE 1] Applying V1 Hotpatch (v1.1.0-SECURITY-HOTFIX)...
[+] Active V1 Status: GO_SERVICE_V1_HOTPATCHED | Version: v1.1.0-SECURITY-HOTFIX

>>> [STAGE 2] Applying V2 Hotpatch (v2.0.0-PERF-UPGRADE)...
[+] Active V2 Status: GO_SERVICE_V2_OPTIMIZED_RCU | Version: v2.0.0-PERF-UPGRADE

>>> [STAGE 3] Applying V3 Hotpatch (v3.0.0-PRODUCTION)...
[+] Active V3 Status: GO_SERVICE_V3_ENTERPRISE_ASYNC | Version: v3.0.0-PRODUCTION

>>> [STAGE 4] Atomically reverting all livepatches back to V0 baseline...
[+] Post-Revert V0 Status: ORIGINAL_UNPATCHED_GO_SERVICE | Version: v1.0.0-GA

[+] Load Verification: 4,030 successful concurrent queries, 0 errors
==============================================================================
   RESULT: GOLANG MULTI-VERSION CONTINUOUS LIVEPATCHING 100% SUCCESS!         
==============================================================================
```
