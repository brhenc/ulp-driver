# ulp-driver: ULP Examples & Usage Suite

This directory contains standalone, runnable examples designed to demonstrate how **Userspace Livepatching (ULP)** works in practice.

Unlike black-box automated test suites, these examples serve as an **executable reference and tutorial**, encapsulating the exact operational procedures for loading the kernel driver, compiling payloads, resolving symbols, hotpatching processes, surviving kernel driver unloads with zero downtime, and reverting cleanly.

---

## Quickstart: Running All Examples

To build and execute all four examples end-to-end:

```bash
sudo ./examples/test_all_examples.sh
```

**Output Summary:**
```text
================================================================================
                         FINAL EXECUTION SUMMARY                                
================================================================================
  [PASS]  01_basic_c_service (1s) - Basic C Service Livepatching & Reversion
  [PASS]  02_driver_resumption_zero_downtime (1s) - Driver Unload & State Resumption
  [PASS]  03_rust_livepatch (2s) - Rust Application Livepatching & ABI Safety
  [PASS]  04_exec_rule_persistence (0s) - In-Kernel Persistent Execve Startup Rules
--------------------------------------------------------------------------------
  Total Suites Executed: 4 / 4
  Overall Status:        all passed
  Total Time Elapsed:    4 seconds
================================================================================
```

---

## Directory Index

| Example | Directory | Target Language | Core Concept Demonstrated |
| :--- | :--- | :--- | :--- |
| **01** | [`01_basic_c_service/`](./01_basic_c_service/) | C | Basic runtime injection, function patching, and clean rollback. |
| **02** | [`02_driver_resumption_zero_downtime/`](./02_driver_resumption_zero_downtime/) | C | Kernel driver unload/reload (`allow_resumption=1`, `resume=1`) while the service keeps serving traffic. |
| **03** | [`03_rust_livepatch/`](./03_rust_livepatch/) | Rust | Rust ABI considerations (`#[no_mangle]`, `extern "C"`), cdylib injection, and PIE symbol resolution. |
| **04** | [`04_exec_rule_persistence/`](./04_exec_rule_persistence/) | C | In-kernel persistent `execve` startup rules (`ulp_ctl add-rule`). |

---

## Example 1: Basic C Service Livepatching

* **Path**: [`examples/01_basic_c_service/`](./01_basic_c_service/)
* **Objective**: Demonstrates how to livepatch a running C daemon listening on a UNIX domain socket.

### Step-by-Step Walkthrough

1. **Write Target Function**:
   Target functions must be non-inlined and 16-byte aligned (the driver requires 8-byte aligned patch sites):
   ```c
   __attribute__((noinline, aligned(16)))
   const char *get_service_status(void) {
       return "STATUS: v1.0.0 [UNPATCHED] | mode=standard | rate_limit=100 req/s\n";
   }
   ```

2. **Write Replacement Function** (`patch_payload.c`):
   ```c
   __attribute__((noinline, aligned(16)))
   const char *livepatch_get_service_status(void) {
       return "STATUS: v1.0.1 [LIVEPATCHED] | mode=enterprise_hardened | rate_limit=5000 req/s\n";
   }
   ```

3. **Compile**:
   ```bash
   gcc -O2 -Wall -fno-omit-frame-pointer -no-pie -o target_service target_service.c
   gcc -shared -fPIC -O2 -Wall -o patch_payload.so patch_payload.c
   ```

4. **Launch & Verify Baseline**:
   ```bash
   ./target_service &
   PID=$!
   ./target_service --query
   # Output: STATUS: v1.0.0 [UNPATCHED] ...
   ```

5. **Inject Shared Object**:
   Use `ulp_inject` (sub-millisecond `ptrace` remote `dlopen`):
   ```bash
   ulp_inject $PID ./patch_payload.so
   ```

6. **Calculate Addresses**:
   * Target function address: `nm target_service | grep -w get_service_status`
   * Patch function address: Base from `/proc/$PID/maps` + offset from `nm -D patch_payload.so`.

7. **Apply Livepatch**:
   ```bash
   ulp_ctl apply $PID example_patch get_service_status $TARGET_VADDR $PATCH_VADDR 16
   ```

8. **Verify Live Output**:
   ```bash
   ./target_service --query
   # Output: STATUS: v1.0.1 [LIVEPATCHED] ...
   ```

9. **Revert Livepatch**:
   ```bash
   ulp_ctl revert $PID $TARGET_VADDR
   ./target_service --query
   # Output: STATUS: v1.0.0 [UNPATCHED] ...
   ```

---

## Example 2: Kernel Driver Resumption Across Module Reloads

* **Path**: [`examples/02_driver_resumption_zero_downtime/`](./02_driver_resumption_zero_downtime/)
* **Objective**: Demonstrates how to upgrade or patch `ulp_driver.ko` itself without dropping active userspace livepatches or interrupting production services.

### The Resumption Invariant

```
 [ LIVEPATCHED USERSPACE DAEMON (PID 27315) ]
        │  ▲
        │  │ Active queries executed directly in Ring 3
        ▼  │ (Trampoline executes autonomously)
 ───────────────────────────────────────────────────────────── (Kernel Boundary)
   [ ULP KERNEL DRIVER (ulp_driver.ko) ]
        │
        ├─► rmmod ulp_driver
        │     └─► Serializes active patches to /run/ulp/state.bin
        │     └─► Driver UNLOADED from kernel
        │
        ├─► [DRIVER OFFLINE / UPGRADING]
        │     └─► Daemon keeps serving patched code with the driver unloaded
        │
        └─► insmod ulp_driver.ko resume=1 allow_resumption=1
              └─► Deserializes /run/ulp/state.bin
              └─► Verifies memory trampolines and re-adopts patches
              └─► Re-populates /proc/ulp_patches
```

### Execution Procedure

1. **Load Driver with Resumption Enabled**:
   ```bash
   insmod ulp_driver.ko dev_mode=1 allow_resumption=1 resume=1
   ```

2. **Livepatch Worker Daemon**:
   ```bash
   ulp_ctl apply $WORKER_PID resumption_patch process_work_unit $TARGET $PATCH 16
   ```

3. **Unload Driver**:
   ```bash
   rmmod ulp_driver
   lsmod | grep ulp_driver  # Empty! Module is completely absent.
   ls -la /run/ulp/state.bin # Snapshot verified.
   ```

4. **Verify Continuous Query Processing**:
   ```bash
   # Service continues executing hotpatched code with zero dropped requests!
   ./worker_service --query 10
   ```

5. **Reload Driver with Resumption**:
   ```bash
   insmod ulp_driver.ko dev_mode=1 resume=1 allow_resumption=1
   cat /proc/ulp_patches    # Re-adopted automatically!
   ```

6. **Clean Revert**:
   ```bash
   ulp_ctl revert $WORKER_PID $TARGET
   ```

---

## Example 3: Rust Application Livepatching

* **Path**: [`examples/03_rust_livepatch/`](./03_rust_livepatch/)
* **Objective**: Demonstrates livepatching modern compiled Rust services.

### Rust ABI & Compiler Invariants

1. **Symbol Demangling (`#[no_mangle]`)**:
   Rust v0 / legacy symbol mangling (`_RNv...`) alters function names. Using `#[no_mangle]` preserves standard C linkage names.
2. **Inlining Prevention (`#[inline(never)]`)**:
   Forces `rustc` / LLVM to emit a distinct function entry point.
3. **Preventing Intra-Crate Constant Folding**:
   If a Rust function returns a constant literal and is called in the same crate, LLVM's IPO passes may inline the literal value at the callsite. Calling through `std::hint::black_box()` or cross-crate dispatch ensures authentic dynamic function invocation.

```rust
// Target in rust_daemon.rs
#[no_mangle]
#[inline(never)]
pub extern "C" fn rust_get_rate_limit() -> u32 {
    100
}

// Replacement in patch_rust.rs (cdylib)
#[no_mangle]
#[inline(never)]
pub extern "C" fn livepatch_rust_get_rate_limit() -> u32 {
    5000
}
```

---

## Example 4: Persistent In-Kernel Execve Startup Rules

* **Path**: [`examples/04_exec_rule_persistence/`](./04_exec_rule_persistence/)
* **Objective**: Demonstrates automatic startup livepatching for new processes without manual injection.

### Workflow

1. **Register In-Kernel Rule**:
   ```bash
   ulp_ctl add-rule /usr/bin/task_worker auto_sec_fix check_security_status 0x401170 0 16 0 1
   ```
   *(Passing `patch_vaddr=0` instructs the driver to inject an atomic return-zero stub: `endbr64; xor %eax, %eax; ret`)*

2. **Inspect Kernel Rules**:
   ```bash
   ulp_ctl list-rules
   cat /proc/ulp_rules
   ```

3. **Execute Target Binary**:
   ```bash
   /usr/bin/task_worker
   # Output: WORKER_STATUS: status=0 (SECURED_BY_IN_KERNEL_RULE)
   ```
   The kernel kprobe intercepts `execve()` and queues a `task_work` callback that writes the patch bytes before userspace initialization.

4. **Delete Rule**:
   ```bash
   ulp_ctl del-rule /usr/bin/task_worker 0x401170
   /usr/bin/task_worker
   # Output: WORKER_STATUS: status=1 (LEGACY_UNPATCHED)
   ```
