# Multi-Language Userspace Livepatching Guide: C, C++, Rust & Golang

**Module:** Language Runtimes & ABI Integration  
**Supported Languages:** C, C++, Rust 1.85+, Go 1.18 – Go 1.24+, Zig, Swift  
**Path:** `docs/hacking/03_MULTI_LANGUAGE_SUPPORT_GUIDE.md`  

---

## 1. Overview

Userspace Livepatching (ULP) is **completely language-agnostic** at the hardware machine-code level. However, each language compiler imposes unique ABI, symbol mangling, memory layout, and runtime scheduling conventions.

This guide details the exact patterns and rules for livepatching across all four primary systems languages.

---

## 2. Livepatching C Daemons (HAProxy, PostgreSQL, MariaDB)

### 2.1 ABI & Calling Convention
* **ABI**: System V AMD64 ABI on x86_64 (`RDI, RSI, RDX, RCX, R8, R9` for arguments, `RAX, RDX` for returns, `R11` for scratch).
* **Symbol Resolution**: Direct ELF symbol lookup via `.dynsym` / `.symtab` using `nm` or `dlsym`.

### 2.2 Best Practices:
* **Function Granularity**: Ensure critical hotfix targets are compiled with standard stack frames (`-fno-omit-frame-pointer`).
* **Static Functions**: Static functions not exported in `.dynsym` are resolved via `.symtab` or base VMA + static ELF offset.

---

## 3. Livepatching C++ Daemons (MariaDB 11.8, Percona)

### 3.1 Name Mangling & Symbol Demangling
C++ mangles function names with namespaces and parameter types (e.g. `_Z19get_max_connectionsv`).
* **Resolution**: ULP resolves mangled symbols directly via ELF symbol table lookups (`nm -D` or `nm`) or demangles using `abi::__cxa_demangle`.

### 3.2 Virtual Methods & Vtables
* **Mechanism**: Virtual calls dispatch through the object's vtable (`vptr[slot]()`).
* **Zero Extra Cost**: Because vtable slots hold direct function pointers to the function preamble, placing an atomic 16-byte ULP trampoline at the function entry point intercepts **both direct calls and virtual calls simultaneously** without mutating the vtable!

### 3.3 Class Layout Immutability
Never add non-static data members to an existing C++ class at runtime (which changes `sizeof(Class)`). Use **`ulp_shadow_alloc(this, field_id, size, init_data)`** to attach dynamic member state to the `this` pointer.

---

## 4. Livepatching Rust Daemons (pgrust)

### 4.1 Rust ABI vs `extern "C"`
* **Public / FFI Interfaces**: Declare with `#[no_mangle] pub extern "C" fn func_name(...)` to enforce the platform C ABI.
* **Internal Rust Functions**: Internal `"Rust"` ABI functions pass arguments in LLVM-optimized registers. ULP trampolines strictly use the platform scratch register (`%r11` on x86, `X16` on ARM64), preserving all caller-saved registers.

### 4.2 Multi-Generation Livepatching Pattern ($V_0 \to V_1 \to V_2 \to V_3$)
As demonstrated in [`test_multi_version_continuous_suite.py`](/test_multi_version_continuous_suite.py):
* **$V_1$ Generation**: Implements CVE security validation.
* **$V_2$ Generation**: Attaches dynamic shadow telemetry state (`ulp_shadow_alloc`).
* **$V_3$ Generation**: Activates SIMD / AVX2 query execution paths.
* **$V_0$ Rollback**: Restores original baseline atomically.

---

## 5. Livepatching Golang Daemons (Go `ABIInternal`)

### 5.1 The `ABIInternal` Register Model
Starting with Go 1.17+, the Go compiler uses register-based parameter passing on x86_64:

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
└────────────────────────────────────────────────────────┘
```

> [!CRITICAL]
> **Never Clobber the Pinned `g` Register**: In Go, `R14` (on x86_64) or `X28` (on ARM64) holds the pointer to `runtime.g`. Modifying it will immediately crash the Go runtime during goroutine scheduling! ULP trampolines strictly use register **`R11`**.

### 5.2 Dynamic Goroutine Stacks (`morestack`)
Go functions begin with a stack guard check against `g.stackguard0`. ULP places the trampoline directly at instruction offset `0x00`, executing *before* the stack split check, seamlessly running within the active goroutine frame.

### 5.3 Stripped Binary Symbol Resolution via `.gopclntab`
Even if a Go binary is stripped (`-ldflags="-s -w"`), the `.gopclntab` table remains embedded for GC stack maps and panic traces. [`go_sym_resolver.py`](/go-livepatch-bench/go_sym_resolver.py) parses this structure to resolve symbol virtual addresses automatically.

---

## 6. Language Feature Comparison Matrix

| Operational Dimension | C | C++ | Rust | Golang |
| :--- | :--- | :--- | :--- | :--- |
| **Calling Convention** | System V AMD64 | System V AMD64 (`this` in RDI) | System V / Rust ABI | `ABIInternal` (RAX, RBX...) |
| **Symbol Resolution** | `.symtab` / `.dynsym` | Mangled `_Z...` symbols | Mangled `_ZN...` / `_R...` | `.gopclntab` program counter table |
| **Stack Architecture** | Fixed OS Stack | Fixed OS Stack | Fixed OS Stack | Dynamic Segmented Stacks (`morestack`) |
| **Concurrency Model** | 1:1 Kernel Threads | 1:1 Kernel Threads | 1:1 Kernel Threads / Tokio | M:N Goroutine Scheduler |
| **Preemption Model** | OS Preemption | OS Preemption | Cooperative Async | Signal-Based (`SIGURG`) Preemption |
| **Shadow Memory Support**| Native `ulp_shadow` | Native `ulp_shadow` | Native `ulp_shadow` | Native `ulp_shadow` |
| **Livepatch Cost** | Baseline | **Zero Extra Cost** | **Zero Extra Cost** | **Zero Extra Cost** |
