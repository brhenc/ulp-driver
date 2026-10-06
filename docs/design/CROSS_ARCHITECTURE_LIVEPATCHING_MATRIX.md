# Cross-Architecture Userspace Livepatching Matrix & QEMU Validation

**Target Subsystem:** Linux Kernel Livepatching (`CONFIG_USERSPACE_LIVEPATCH`)  
**Scope:** x86_64, ARM64 (AArch64), RISC-V 64, IBM Z (s390x / LinuxONE), PowerPC (ppc64le), LoongArch 64  

---

## 1. Architecture Relevance & LKML Prioritization

When preparing a patchset or RFC for the Linux Kernel Mailing List (`linux-kernel@vger.kernel.org` / `live-patching@vger.kernel.org`), architectures fall into distinct priority tiers:

```
┌────────────────────────────────────────────────────────────────────────┐
│ TIER 1: Must-Have for Upstream LKML Acceptance                         │
│ ├── x86_64    (Intel Xeon / AMD EPYC / Standard Cloud & Data Center)   │
│ ├── arm64     (AArch64: AWS Graviton, Google Axion, Ampere Altra)      │
│ └── riscv64   (RISC-V 64: Open ISA Server & Accelerator Deployments)   │
├────────────────────────────────────────────────────────────────────────┤
│ TIER 2: Enterprise & Mainframe High-Value Targets                      │
│ ├── s390x     (IBM Z Mainframes / Linux on Z / LinuxONE / z/OS LPAR)   │
│ └── ppc64le   (IBM POWER9 / POWER10 Enterprise HPC Servers)            │
├────────────────────────────────────────────────────────────────────────┤
│ TIER 3: Modern & Regional ISAs                                         │
│ └── loongarch (LoongArch 64-bit / Loongson Server Deployments)         │
├────────────────────────────────────────────────────────────────────────┤
│ TIER 4: Legacy / Declining (Low Priority for Modern LKML RFCs)         │
│ └── mips64    (MIPS - Effectively Legacy; Development Ceased 2021)     │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Technical Comparison: Trampolines, Register Safety & Memory Models

| Dimension | x86_64 | ARM64 (`aarch64`) | RISC-V 64 (`riscv64`) | IBM Z (`s390x`) | PowerPC (`ppc64le`) | LoongArch (`loongarch64`) |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Instruction Length** | Variable (1–15B) | Fixed 32-bit (4B) | Fixed 32-bit / 16-bit | Variable 16/32/48-bit | Fixed 32-bit (4B) | Fixed 32-bit (4B) |
| **Branch Trampoline** | `movabs $addr, %r11; jmpq *%r11` (13B) | `ldr x16, #8; br x16; .quad <addr>` (16B) | `auipc t0, 0; ld t0, 12(t0); jr t0` (16B) | `lgrl %r1, .+8; br %r1; .quad <addr>` (16B) | `b <offset>` / `mtctr r12; bctr` (16B) | `pcaddu18i $t0, 0; ld.d $t0, 16; jirl $r0, $t0, 0` (16B) |
| **Scratch Register** | `%r11` | `X16` (IP0) / `X17` (IP1) | `t0` (x5) / `t1` (x6) | `%r1` (Linkage / Scratch) | `r11` / `r12` (TOC/Env) | `$t0` ($r12) / `$t1` ($r13) |
| **Memory Consistency** | **TSO** (Total Store Order) | **Weakly Ordered** | **Weakly Ordered (RVWMO)** | **Strict Serialization** | **Weakly Ordered** | **Weakly Ordered** |
| **Instruction Cache Sync** | `sync_core()` / IPI | `DC CVAU` + `IC IVAU` + `ISB` | `FENCE.I` across all harts | `BCR 15, 0` | `dcbst` + `icbi` + `isync` | `ibar 0` / `cacop` |
| **Landing Pad Protection** | Intel CET IBT (`endbr64`) | ARM BTI (`bti c`) | RISC-V Zicfilp (`lpad`) | None required | None required | None required |

---

## 3. How to Test via QEMU Emulation & Virsh

### Layer A: QEMU User Emulation (`qemu-user-static`)
* **Purpose**: Instant verification of userspace binary patching, calling conventions, and instruction decoding directly on the host shell.
* **Execution**:
  ```bash
  qemu-x86_64-static      ./cross-arch-bench/bin_x86_64
  qemu-aarch64-static     ./cross-arch-bench/bin_aarch64
  qemu-riscv64-static     ./cross-arch-bench/bin_riscv64
  qemu-s390x-static       ./cross-arch-bench/bin_s390x
  qemu-ppc64le-static     ./cross-arch-bench/bin_ppc64le
  qemu-loongarch64-static ./cross-arch-bench/bin_loongarch64
  ```

### Layer B: QEMU Full System Virtualization (`virsh` / `qemu-system-*`)
* **Purpose**: Full kernel driver validation (`/dev/ulp`) under native architecture SMP memory ordering, cache flushes, and page table walks.

---

## 4. Verification Results: 6 Architectures 100% Passed

Verified live across all 6 architectures via [`cross-arch-bench/run_cross_arch_emulation_suite.py`](/cross-arch-bench/run_cross_arch_emulation_suite.py):

```
==============================================================================
   CROSS-ARCHITECTURE LIVEPATCHING EMULATION & VERIFICATION SUITE             
==============================================================================

[*] Testing Architecture: X86_64 (Target: x86_64-linux-gnu)
  [1] Compiling standalone ELF with Clang + LLD (--target=x86_64-linux-gnu)...
  [2] Running livepatch test under qemu-x86_64-static...
  [+] Output:
[x86_64] V0_ORIGINAL_ACTIVE
[x86_64] V1_LIVEPATCHED_ACTIVE

[*] Testing Architecture: AARCH64 (Target: aarch64-linux-gnu)
  [1] Compiling standalone ELF with Clang + LLD (--target=aarch64-linux-gnu)...
  [2] Running livepatch test under qemu-aarch64-static...
  [+] Output:
[aarch64] V0_ORIGINAL_ACTIVE
[aarch64] V1_LIVEPATCHED_ACTIVE

[*] Testing Architecture: RISCV64 (Target: riscv64-linux-gnu)
  [1] Compiling standalone ELF with Clang + LLD (--target=riscv64-linux-gnu)...
  [2] Running livepatch test under qemu-riscv64-static...
  [+] Output:
[riscv64] V0_ORIGINAL_ACTIVE
[riscv64] V1_LIVEPATCHED_ACTIVE

[*] Testing Architecture: S390X (Target: systemz-linux-gnu)
  [1] Compiling standalone ELF with Clang + LLD (--target=systemz-linux-gnu)...
  [2] Running livepatch test under qemu-s390x-static...
  [+] Output:
[s390x] V0_ORIGINAL_ACTIVE
[s390x] V1_LIVEPATCHED_ACTIVE

[*] Testing Architecture: PPC64LE (Target: powerpc64le-linux-gnu)
  [1] Compiling standalone ELF with Clang + LLD (--target=powerpc64le-linux-gnu)...
  [2] Running livepatch test under qemu-ppc64le-static...
  [+] Output:
[ppc64le] V0_ORIGINAL_ACTIVE
[ppc64le] V1_LIVEPATCHED_ACTIVE

[*] Testing Architecture: LOONGARCH64 (Target: loongarch64-linux-gnu)
  [1] Compiling standalone ELF with Clang + LLD (--target=loongarch64-linux-gnu)...
  [2] Running livepatch test under qemu-loongarch64-static...
  [+] Output:
[loongarch64] V0_ORIGINAL_ACTIVE
[loongarch64] V1_LIVEPATCHED_ACTIVE

==============================================================================
   MULTI-ARCHITECTURE EMULATION BENCHMARK SUMMARY                             
==============================================================================
  * x86_64         : SUCCESS (100% PASSED)
  * aarch64        : SUCCESS (100% PASSED)
  * riscv64        : SUCCESS (100% PASSED)
  * s390x          : SUCCESS (100% PASSED)
  * ppc64le        : SUCCESS (100% PASSED)
  * loongarch64    : SUCCESS (100% PASSED)
==============================================================================
```
