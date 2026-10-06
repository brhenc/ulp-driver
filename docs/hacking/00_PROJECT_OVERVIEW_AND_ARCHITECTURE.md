# ulp-driver: Developer Master Architecture Blueprint

**Module:** Architecture & Overview  
**Path:** `docs/hacking/00_PROJECT_OVERVIEW_AND_ARCHITECTURE.md`  
**Target Audience:** Kernel Hackers, Systems Engineers, Livepatch Maintainers  

---

## 1. Vision & Core Philosophy

**ulp-driver** expands on userspace livepatching (ULP) to achieve a radical operations paradigm: **Continuous Daemon Evolution without Process Restarts**.

Traditional software deployment relies on CI/CD compiling a new binary, tearing down the running daemon process, and spinning up a new one. This model incurs severe operational penalties:
* **Connection Drops / TCP Reset Storms**: In-flight client transactions are aborted or drained.
* **Cold Cache / Buffer Pool Thrashing**: Database buffer pools (e.g. InnoDB 1 TB cache), query plan caches, and TLS session tickets are evicted.
* **Maintenance Windows & Outage Windows**: DBA interventions require late-night coordination.

**The ULP Vision**:
Instead of replacing the running binary on disk and restarting, the running process is continuously updated in-memory via userspace livepatches across multiple software generations ($V_0 \to V_1 \to V_2 \to V_3 \dots \to V_n$), with 100% reversible, 1-click atomic rollback to any prior state.

```
 Traditional CI/CD: [ Build ] ──► [ Kill Process ] ──► [ Cold Restart ] ──► [ Cache Rebuild ]
                                            ▲
                                   (Downtime & Outage)

 ULP Architecture:  [ Running Process (PID) ]
                           │
                           ├──► [ Apply V1 (CVE Hotfix) ]      ──► 0 µs downtime, 0 query loss
                           ├──► [ Apply V2 (RCU Perf Upgrade) ] ──► 0 µs downtime, 0 query loss
                           ├──► [ Apply V3 (Async Features) ]  ──► 0 µs downtime, 0 query loss
                           └──► [ Atomic Revert to V0 ]        ──► 1-key instant rollback
```

---

## 2. End-to-End System Architecture

The ULP stack spans four distinct execution tiers:

```
┌────────────────────────────────────────────────────────────────────────┐
│ Tier 4: Operator & Automation Layer                                    │
│ ├── Curses Terminal UI: tools/ulp_tui.py / ulp-tui.py                        │
│ ├── Command-Line Tools: ulp_ctl, go_sym_resolver.py                    │
│ └── Cryptographic Trust: Cosign (ECDSA-P256) & GPG (RSA-3072) / Rekor   │
├────────────────────────────────────────────────────────────────────────┤
│ Tier 3: Userspace Injection & Trampoline Engine                        │
│ ├── Soft-Realtime Injector: ulp_inject.c (Sub-2ms dlopen & sys_mmap)   │
│ ├── Shadow Variable Subsystem: ulp_shadow.h (RCU Striped Hash Tables)  │
│ └── Target Daemons: pgrust (Rust), mariadbd (C++), postgres, haproxy,  │
│                     server_go (Golang ABIInternal)                     │
├────────────────────────────────────────────────────────────────────────┤
│ Tier 2: Kernel ULP Driver Subsystem (/dev/ulp)                         │
│ ├── Module: ulp-driver/ulp_driver.c (GPL-2.0-only)                     │
│ ├── Atomic 8-Byte Text Poke Engine + sync_core() SMP Invalidation      │
│ ├── Fail-Closed Arming State Machine & Maintenance Window TTL Timer    │
│ ├── Plan 9 VFS Event Ring Buffer (Telemetry Stream to /dev/ulp)        │
│ └── Sysctl Security Ratchet (0=Off, 1=Same-UID, 2=Root-Only, 3=Locked) │
├────────────────────────────────────────────────────────────────────────┤
│ Tier 1: Hardware CPU & ISA Backend                                     │
│ ├── Supported ISAs: x86_64, aarch64, riscv64, s390x, ppc64le, loongarch│
│ └── Memory Models: TSO (x86_64) vs Weakly Ordered (ARM64, RISC-V, PPC) │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 3. Repository Directory Structure

```
ulp-driver/
├── docs/                                  # Complete Technical & Design Documentation
│   ├── hacking/                           # [THIS DIRECTORY] Deep developer & kernel hacking guides
│   ├── design/                            # Advanced database patterns & architecture matrices
│   ├── guides/                            # Operator guides, Go/Rust livepatch specifications
│   └── writeups/                          # Deep-dive benchmark writeups & case studies
├── ulp-driver/                            # Kernel Driver Subsystem & Low-Level Tooling
│   ├── ulp_driver.c                       # Hardened Linux kernel module (2,080+ LOC)
│   ├── ulp_uapi.h                         # Kernel-Userspace UAPI definitions
│   ├── ulp_ctl.c                          # CLI control tool (apply, revert, list, arm, disarm)
│   ├── ulp_inject.c                       # Sub-2ms thread-safe DSO & raw machine code injector
│   ├── ulp_shadow.h                       # Lockless striped RCU shadow variable memory allocator
│   └── Makefile                           # Kernel module build rules
├── rust-livepatch-bench/                  # Rust (pgrust) Continuous Livepatching Benchmark
│   ├── Cargo.toml                         # Rust workspace definition
│   ├── src/bin/pgrust_daemon.rs           # PostgreSQL wire-compatible Rust daemon
│   ├── patch_pgrust_v1/                   # V1 Generation (CVE Hotfix)
│   ├── patch_pgrust_v2/                   # V2 Generation (Shadow Metrics)
│   └── patch_pgrust_v3/                   # V3 Generation (AVX2 SIMD Query Acceleration)
├── go-livepatch-bench/                    # Golang Continuous Livepatching Suite
│   ├── main.go                            # High-concurrency Go REST microservice
│   ├── go_sym_resolver.py                 # Stripped Go binary .gopclntab parser
│   └── test_go_continuous_livepatch.py    # Multi-version concurrent Go test harness
├── mariadb-livepatch-bench/               # MariaDB 11.8 C++ Livepatch Suite
│   ├── patch_mariadb_maxconn.c            # Dynamic max_connections function livepatch
│   ├── update_socket_backlog.c            # Safe in-process socket listen backlog expansion
│   └── test_socket_backlog_live_expansion.py # Live ss -tlpn Send-Q expansion test harness
├── postgres-livepatch-bench/              # PostgreSQL 17 multi-version livepatch modules
├── haproxy-multi-patch/                   # HAProxy 3.0 multi-commit livepatch modules
├── cross-arch-bench/                      # 6-Architecture QEMU Emulation Verification Suite
│   └── run_cross_arch_emulation_suite.py  # Automated compiler & emulator runner
├── tools/ulp_tui.py / ulp-tui.py                # Full-featured Curses Operator Terminal UI
├── tests/test_multi_version_continuous_suite.py # End-to-end continuous validation suite
└── tools/ulp_crypto_verifier.py                 # Cosign & GPG cryptographic verification tool
```

---

## 4. Git Branching Strategy & Conventions

* **`master`**: Stable baseline.
* **`rust-support`**: Core Rust livepatching, shadow memory allocator, MariaDB socket backlog expansion.
* **`golang-support`**: Active development branch containing Golang `ABIInternal` support, cross-architecture test suites (x86_64, aarch64, riscv64, s390x, ppc64le, loongarch64), and developer hacking documentation.

---

## 5. Coding Rules

The driver follows these constraints (some adapted from JPL's "Power of 10" rules):

1. **Allocate-Before-Commit**: All kernel memory structures are allocated *before* any text modification. A livepatch can never be orphaned in a half-patched state due to kernel OOM.
2. **Atomic 8-Byte Text Poking**: Eliminates `INT3` trap hazards and unhandled `SIGTRAP` signals during patch activation.
3. **Dead PID Reaping**: Background cleanup automatically purges stale patch registry entries when target processes exit, preventing PID reuse memory leaks.
4. **Bounded Loop Iterations**: Explicit upper bounds (`ULP_MAX_LOOP_ITERS = 10000`) on all list and thread traversals.
5. **Clean rwsem Decoupling**: VMA bounds and permissions are validated under `mmap_read_lock`, releasing the lock *before* performing cross-process VM access to prevent deadlocks.
6. **Fail-Closed Arming State Machine**: Maintenance windows auto-expire via timer, locking `/dev/ulp` against unauthorized access.
