# Rust Userspace Livepatching & Concurrency Benchmark (pgrust)

This crate provides the reference implementation, test harness, and multi-threaded stress verification suite for userspace livepatching of **Rust machine code and dynamic data structures** using the ulp-driver Userspace Livepatching (ULP) Linux kernel driver (`/dev/ulp`).

---

## 1. Architecture Overview

Userspace livepatching in Rust presents two distinct challenges:

### A. Machine Code Function Livepatching
Modern Rust binaries compiled on x86_64 utilize standard ELF calling conventions, but compilers (`rustc` 1.85+) emit function prologues with Intel CET (Control-flow Enforcement Technology) `endbr64` landing pads. 

ULP utilizes atomic 16-byte absolute trampolines:
```assembly
endbr64                          ; 4 bytes: CET landing pad
movabs  $0x7fa3bbd1d100, %rax    ; 10 bytes: 64-bit replacement address
jmpq    *%rax                    ; 2 bytes: Indirect branch to replacement
```
The kernel driver (`/dev/ulp`) writes this trampoline atomically while validating thread instruction pointer quiescence across all active threads, ensuring zero instructions are executed mid-patch.

### B. Rust Data Structure Patching via Shadow Variables
In Rust, directly expanding the physical size or changing the memory layout of an allocated struct at runtime violates memory safety:
- Pre-compiled functions hardcode struct field byte offsets (`[rdi + 0x18]`) and struct sizes (`size_of::<T>()`).
- Modifying heap chunk boundaries corrupts allocator metadata and causes immediate segfaults.

**Solution: C ABI-Compatible Lock-Striped Shadow Registry (`UlpShadowRegistry`)**
- Extra fields (e.g. `ShadowMetrics` tracking query quotas and rate-limiting) are stored in an out-of-band concurrent registry indexed by struct heap address (`Arc::as_ptr(&conn) as usize`) and field ID (`0x2001`).
- **256 Lock-Striped Buckets**: Uses `parking_lot::RwLock` across 256 hash buckets, eliminating lock contention under high-concurrency multi-threaded workloads.
- **Dynamic Symbol Resolution**: Exported via C ABI (`ulp_shadow_alloc`, `ulp_shadow_get`, `ulp_shadow_clear_all`) with `-Wl,--export-dynamic`, ensuring runtime livepatch libraries (`libpatch_pgrust.so`) bind directly to the running process's registry without duplicate state or `TypeId` mismatches across dylibs.
- **Deterministic RAII Cleanup**: Integrated into struct destruction (`impl Drop for PgConnection { fn drop(&mut self) { unsafe { self.shadow_clear_all(); } } }`), guaranteeing zero memory leaks upon session termination.

---

## 2. Components

| Component | Path | Description |
| :--- | :--- | :--- |
| **`ulp_shadow` Library** | `src/lib.rs` | Lock-striped shadow variable registry, C ABI exports, and `UlpShadowExt` trait. |
| **`pgrust_daemon`** | `src/bin/pgrust_daemon.rs` | Multi-threaded PostgreSQL-compatible server handling sessions, queries, and shadow metrics. |
| **`pgrust_client`** | `src/bin/pgrust_client.rs` | High-concurrency client generator (16 threads, 50 queries/thread = 800 total). |
| **`patch_pgrust`** | `patch_pgrust/src/lib.rs` | Runtime replacement library (`patch_pgrust_get_version`, `patch_pgrust_process_query`). |
| **Test Harness** | `test_rust_livepatch_pgrust.py` | Automated end-to-end test verifying baseline, livepatch application, stress load, and rollback. |

---

## 3. Verification & Benchmark Results

### Multi-Threaded Stress Test (16 Threads, 800 Queries)
Executed on `debian-13` (Linux 6.12 SMP) and `fedora-44` (Linux 7.1.8 SMP):

```
===============================================================
                 BENCHMARK EXECUTION RESULTS                   
===============================================================
  Target Host             : 192.168.122.171:5433 (debian-13)
  Target Host             : 192.168.122.102:5433 (fedora-44)
  Worker Threads          : 16
  Queries Per Worker      : 50
  Total Query Target      : 800
  Elapsed Time            : 43.728ms
  Successful Requests     : 800 (100.0%)
  Failed Requests         : 0 (0.0%)
  Livepatched Versions Seen: 160 (100% of VERSION calls)
  Shadow Variables Active : 640 (100% of QUERY calls)
===============================================================
[+] SUCCESS: All 800 concurrent requests succeeded with 100% reliability!
```

### Driver Rollback Verification
Reverting patches via `/dev/ulp` restores original binary machine code:
```
[*] Reverting livepatches...
[ulp_ctl] SUCCESS: Kernel reverted livepatch for PID 6278 at 0x560b37c1bfa0
[ulp_ctl] SUCCESS: Kernel reverted livepatch for PID 6278 at 0x560b37c1bfc0
[*] Verifying traffic after livepatch reversion...
  Livepatched Versions Seen: 0
  Shadow Variables Active : 0
  Successful Requests     : 80 (100%)
```

---

## 4. Running the Tests

```bash
# 1. Run unit tests
cargo test --lib

# 2. Build binaries and livepatch library
cargo build
cd patch_pgrust && cargo build --release && cd ..

# 3. Execute automated kernel livepatching test (requires /dev/ulp)
python3 test_rust_livepatch_pgrust.py
```
