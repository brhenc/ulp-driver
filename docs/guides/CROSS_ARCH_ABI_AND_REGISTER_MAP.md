# Cross-Architecture ABI & Register Map Reference for Livepatching

**Supported Architectures:** `x86_64`, `aarch64`, `riscv64`, `s390x`, `ppc64le`, `loongarch64`  
**Supported Runtimes:** C / C++ (System V / Itanium), Rust (`"Rust"` / `"C"` ABI), Golang (`ABIInternal`)  

---

## 1. Why RISC-V Initially Crashed (Root Cause Analysis)

During the cross-architecture benchmark, the initial RISC-V 64 test failed with `code -11` (`SIGSEGV`) due to **page-alignment requirements in the Linux kernel**:

### The Problem:
1. In the Linux kernel (`mm/mprotect.c`), the `sys_mprotect(addr, len, prot)` syscall (syscall 226 on RISC-V) strictly requires the `addr` argument in register `a0` to be **aligned to a 4 KB page boundary (`addr & ~0xFFF`)**.
2. Our unaligned function address (`0x100e4`) caused the kernel to reject the syscall with `-EINVAL`.
3. The memory page containing `.text` remained write-protected (`PROT_READ | PROT_EXEC`).
4. When the store instruction (`sw a1, 0(a0)`) attempted to write the trampoline, the CPU MMU raised a page fault, instantly killing the process with **`SIGSEGV` (Signal 11)**.

### The Fix:
```assembly
# Page-align a0 down to 4096 boundary before sys_mprotect
lla a0, get_version
li  a1, -4096
and a0, a0, a1       # a0 = a0 & ~0xFFF
li  a1, 4096
li  a2, 7            # PROT_READ | PROT_WRITE | PROT_EXEC
li  a7, 226          # sys_mprotect
ecall
```

---

## 2. Rust vs Golang Register Allocation Across All 6 Architectures

```
┌────────────────────────────────────────────────────────────────────────┐
│ Rust Model: Strictly adheres to platform C ABI for public/FFI symbols  │
│ Golang Model: Custom ABIInternal with pinned `g` goroutine registers   │
└────────────────────────────────────────────────────────────────────────┘
```

### Complete Cross-Architecture Register Map

| Architecture | Platform C / Rust Scratch | Go Pinned `g` Register (DO NOT CLOBBER) | Go `ABIInternal` Argument & Return Registers | Go Scratch / Trampoline Reg |
| :--- | :--- | :--- | :--- | :--- |
| **`x86_64`** | `%r11` | **`R14`** (`runtime.g`) | `RAX, RBX, RCX, RDI, RSI, R8, R9, R10` | **`R11`** |
| **`aarch64` (ARM64)** | `X16` (IP0), `X17` (IP1) | **`X28`** (`g`) | `X0, X1, X2, X3, X4, X5, X6, X7 ... X15` | **`X16` / `X17`** |
| **`riscv64`** | `t0` (x5), `t1` (x6) | **`X27`** (`s11` = `g`) | `a0–a7` (x10–x17), `s0–s1`, `s2–s7` | **`t0` (x5) / `t1` (x6)** |
| **`s390x` (IBM Z)** | `%r0`, `%r1` | **`R13`** (`g`) | `R2, R3, R4, R5, R6, R7, R8, R9, R10` | **`R1`** |
| **`ppc64le`** | `r11`, `r12` (TOC/Env) | **`R30`** (`g`) | `R3–R10`, `R14–R17` | **`R11` / `R12`** |
| **`loongarch64`** | `$t0` ($r12), `$t1` ($r13) | **`r22`** (`$s9` = `g`) | `r4–r19` (`$a0–$a7`, `$t0–$t7`) | **`r20` / `r21`** |

---

## 3. Key Golden Rules for Cross-Architecture Livepatches

1. **Rule 1: Never Touch the Pinned `g` Register in Go**:
   * If an injection or trampoline modifies the architecture's `g` register (`R14` on x86, `X28` on ARM64, `X27` on RISC-V, etc.), the Go runtime will crash with a panic or memory fault on the next goroutine context switch or stack check (`CMPQ SP, 16(g)`).
2. **Rule 2: Go Multi-Value Return Values**:
   * A Go string return (`string`) is a 2-word struct `(data_ptr, len)`.
   * A Go slice return (`[]T`) is a 3-word struct `(data_ptr, len, cap)`.
   * In x86_64: `RAX` (ptr), `RBX` (len), `RCX` (cap).
   * In ARM64: `X0` (ptr), `X1` (len), `X2` (cap).
   * In RISC-V: `a0` (ptr), `a1` (len), `a2` (cap).
   * In LoongArch: `$a0` (ptr), `$a1` (len), `$a2` (cap).
3. **Rule 3: Instruction Cache Invalidation on Weak Architectures**:
   * On ARM64, RISC-V, PPC64LE, and LoongArch, CPU instruction pipelines do not automatically snoop data cache stores to executable pages.
   * Modifying instructions requires executing hardware cache clean and invalidation barriers (`ISB`, `FENCE.I`, `isync`, `ibar 0`).
