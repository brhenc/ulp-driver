# Rust livepatching benchmark (pgrust)

This crate is a test bed for livepatching Rust code and adding per-object state (shadow variables) to a running Rust process with ulp-driver (`/dev/ulp`). It contains a small multi-threaded server, a client load generator, a patch library, and a test harness.

---

## 1. Architecture Overview

Userspace livepatching in Rust presents two distinct challenges:

### A. Machine Code Function Livepatching
Rust binaries on x86_64 use the standard ELF calling conventions. When built with CET (`-Z cf-protection=branch` or a toolchain that enables it), function entries start with an `endbr64` landing pad.

ULP overwrites the function entry with a 16-byte absolute trampoline:
```assembly
endbr64                          ; 4 bytes: CET landing pad
movabs  $0x7fa3bbd1d100, %rax    ; 10 bytes: 64-bit replacement address
jmpq    *%rax                    ; 2 bytes: Indirect branch to replacement
```
The 16-byte write is not atomic. `ulp_ctl apply`/`revert` therefore stop every thread of the target with ptrace first, retry while any thread's instruction pointer is inside the patch window, and only then ask the driver to write. Return addresses inside the window are not checked. Other callers of `/dev/ulp` (`ulp_tui.py`, `libulp_preload`) do not stop the threads.

### B. Rust Data Structure Patching via Shadow Variables
A live patch cannot change the size or layout of a struct that is already allocated:
- Existing code has field offsets (`[rdi + 0x18]`) and sizes (`size_of::<T>()`) compiled in.
- Growing a heap allocation in place would corrupt allocator metadata.

Instead, new fields go in a side table, `UlpShadowRegistry`, as in kernel livepatch shadow variables:
- Extra fields (e.g. `ShadowMetrics` tracking query quotas and rate-limiting) are stored in an out-of-band concurrent registry indexed by struct heap address (`Arc::as_ptr(&conn) as usize`) and field ID (`0x2001`).
- The registry has 256 buckets, each behind a `parking_lot::RwLock`, to reduce lock contention between threads.
- The registry is exported through a C ABI (`ulp_shadow_alloc`, `ulp_shadow_get`, `ulp_shadow_clear_all`) and linked with `-Wl,--export-dynamic`, so the patch library (`libpatch_pgrust.so`) binds to the running process's registry instead of carrying its own copy (which would also break `TypeId` comparisons across dylibs).
- Shadow entries are freed when the owning struct is dropped (`impl Drop for PgConnection { fn drop(&mut self) { unsafe { self.shadow_clear_all(); } } }`). This only covers structs whose `Drop` impl calls it.

---

## 2. Components

| Component | Path | Description |
| :--- | :--- | :--- |
| `ulp_shadow` library | `src/lib.rs` | Lock-striped shadow variable registry, C ABI exports, and `UlpShadowExt` trait. |
| `pgrust_daemon` | `src/bin/pgrust_daemon.rs` | Multi-threaded toy server with a PostgreSQL-like text protocol (sessions, queries, shadow metrics). |
| `pgrust_client` | `src/bin/pgrust_client.rs` | Concurrent client load generator (16 threads, 50 queries/thread = 800 total). |
| `patch_pgrust` | `patch_pgrust/src/lib.rs` | Runtime replacement library (`patch_pgrust_get_version`, `patch_pgrust_process_query`). |
| Test harness | `test_rust_livepatch_pgrust.py` | Automated end-to-end test verifying baseline, livepatch application, stress load, and rollback. |

---

## 3. Observed results

### Multi-threaded run (16 threads, 800 queries)
Output from one run on a Debian 13 test VM (Linux 6.12). It shows that, in this run, all requests succeeded while patched; it is not a performance benchmark.

```
===============================================================
                 BENCHMARK EXECUTION RESULTS                   
===============================================================
  Target Host             : <host>:5433
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

### Revert
After `ulp_ctl revert`, the original code runs again:
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

# 3. Run the livepatch test (requires the driver loaded, /dev/ulp)
#    Note: the script has hard-coded /root/ulp-driver paths; adjust them first.
python3 test_rust_livepatch_pgrust.py
```
