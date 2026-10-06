# Linux Kernel Upstream Hygiene, Sanitizers & Shadow Variables Lifecycle

**ulp-driver: Userspace Livepatching Subsystem**  
**Document**: `docs/design/UPSTREAM_HYGIENE_AND_SHADOW_VARIABLES.md`  
**Status**: Architectural Specification & Implementation Guidelines  
**Audience**: Kernel Module Contributors, Systems Engineers, Livepatch Authors  

---

## 1. Upstream Linux Kernel Contribution Rules & Hygiene Standards

When submitting kernel drivers or subsystems to the upstream Linux kernel mailing list (LKML), code must conform to the strict standards established by Linus Torvalds and kernel maintainers (`Documentation/process/submitting-patches.rst`, `Documentation/process/coding-style.rst`).

### A. The Golden Rules of Kernel Code Quality

1. **`checkpatch.pl` Strict Cleanliness**:
   Every patch must be checked against `scripts/checkpatch.pl --strict --no-tree -f <file>`. Key rules enforced:
   * **Never Initialize Statics to Zero / NULL**:
     ```c
     /* INCORRECT (Triggers checkpatch error: "do not initialise statics to 0") */
     static u32 g_arm_nonce = 0;
     static unsigned long g_armed_until = 0;

     /* CORRECT (Statics automatically reside in .bss and are zeroed at load) */
     static u32 g_arm_nonce;
     static unsigned long g_armed_until;
     ```
   * **Deprecate `strncpy()` in Favor of `strscpy()`**:
     `strncpy()` is formally deprecated in the Linux kernel. It fails to guarantee NUL-termination if the source exceeds buffer length and wastes CPU cycles filling the remaining destination buffer with zeroes.
     ```c
     /* INCORRECT */
     strncpy(dest, src, sizeof(dest) - 1);

     /* CORRECT */
     strscpy(dest, src, sizeof(dest));
     ```
     `strscpy()` returns the number of characters copied (excluding NUL) or `-E2BIG` on truncation, and always guarantees NUL-termination.
   * **Indentation**:
     Hard tabs (8 characters wide) are strictly mandatory. 4-space indentation is rejected.
   * **Zero Version Guards for Upstream Submissions**:
     Out-of-tree drivers use `#if LINUX_VERSION_CODE >= KERNEL_VERSION(...)`. Upstream code must target the tree's current API directly with no version preprocessor conditionals.

2. **Types: Kernel-Internal (`u32`) vs. UAPI (`__u32`)**:
   * **UAPI Headers** (e.g. `ulp_uapi.h` shared with userspace): Must use `__u8`, `__u16`, `__u32`, `__u64` to prevent collisions with userspace libc headers.
   * **Kernel Core** (e.g. `ulp_driver.c`): Must use standard kernel types `u8`, `u16`, `u32`, `u64`.

3. **Static Analysis Verification**:
   * **Sparse (`make C=1`)**: Checks address spaces (`__user`, `__kernel`, `__rcu`) and lock context balance (`__must_hold`).
   * **Smatch (`make CHECK="smatch"`)**: Validates branch reachability, boundary arithmetic, and uninitialized data paths.
   * **Coccinelle (`make coccicheck`)**: Semantic patch checking verifying modern kernel idiom compliance.

---

## 2. Sanitizers: Userspace vs. Kernel Space

Developers familiar with userspace sanitizers (ASan, LSan, MSan, TSan, UBSan) rely on userspace runtime interceptors (`libasan.so`). In the Linux kernel, there is no libc runtime; instead, the kernel provides native, deep compiler-and-hardware-assisted diagnostic subsystems.

### Comprehensive Sanitizer Matrix

| Userspace Sanitizer | Kernel Counterpart | Kernel Config Flag | Architectural Function & Error Detection |
| :--- | :--- | :--- | :--- |
| **AddressSanitizer (ASan)** | **KASAN** (Kernel Address Sanitizer) | `CONFIG_KASAN=y` | Shadow memory tracks every 8 bytes of kernel memory with 1 shadow byte. Catches slab-out-of-bounds, stack-out-of-bounds, and Use-After-Free (UAF) in driver data structures. |
| **LeakSanitizer (LSan)** | **KMEMLEAK** | `CONFIG_DEBUG_KMEMLEAK=y` | Scans kernel memory for orphaned pointer graphs. Detects unreferenced `kmalloc` / `kzalloc` allocations that were never freed. |
| **MemorySanitizer (MSan)** | **KMSAN** | `CONFIG_KMSAN=y` | Tracks uninitialized memory down to bit-level metadata. Detects uninitialized kernel struct fields being copied to userspace via `copy_to_user()`. |
| **ThreadSanitizer (TSan)** | **KCSAN** (Kernel Concurrency Sanitizer) | `CONFIG_KCSAN=y` | Watchpoint-based data race detector. Detects concurrent reads and writes to shared global variables without atomic or lock synchronization. |
| **UndefinedBehavior (UBSan)** | **UBSAN** | `CONFIG_UBSAN=y` | Compiler instrumentation catching signed integer overflows, misaligned pointer accesses, and invalid shifts. |
| *(None)* | **LOCKDEP** (Lock Validator) | `CONFIG_LOCKDEP=y`<br>`CONFIG_PROVE_LOCKING=y` | Tracks lock acquisition order graph across all CPUs. Detects circular deadlocks, lock order inversions, and sleeping-while-atomic hazards before deadlocks occur. |
| *(None)* | **KFENCE** (Electric Fence) | `CONFIG_KFENCE=y` *(Active on Debian 13)* | Low-overhead sampling memory safety guard pages. Runs in production environments with near-zero overhead, catching heap corruptions and UAFs. |

### How `ulp_driver.ko` Interacts with Kernel Sanitizers

* **Automatic Enforcement**: If the host kernel is compiled with `CONFIG_KASAN=y` or `CONFIG_LOCKDEP=y`, loading `ulp_driver.ko` automatically subjects all its `kmalloc`, `list_head`, spinlock, and RCU operations to instrumentation.
* **Sleeping-While-Atomic Safety**: If an operator accidentally calls a sleeping function (`filp_open`, `kernel_write`, `get_user_pages`) while holding `g_patch_lock` (`spinlock_t`), `LOCKDEP` instantly triggers a kernel `BUG: scheduling while atomic` stack trace.
* **Lock Class Keys**: Static spinlocks (`DEFINE_SPINLOCK(g_patch_lock)`) automatically register static lockdep keys, enabling lockdep to track lock hierarchies against rq/vma locks.

---

## 3. Shadow Variables Architecture & Memory Safety

Shadow variables are one of the most powerful and dangerous patterns in livepatching. Originally pioneered by the Linux kernel livepatching project (`klp_shadow`), they solve a fundamental problem:

> **The Livepatch ABI Paradox**: A livepatch often needs to attach new state or fields to an existing struct (e.g. adding a security context or counter to a connection struct). However, expanding `struct Connection` in memory is impossible at runtime, as doing so shifts all field offsets and causes immediate memory corruption across unpatched code.

### The Shadow Variable Solution

Instead of altering the struct layout, the livepatch stores additional fields out-of-band in a concurrent hash registry, indexed by the object's virtual memory address:
```
Key: (object_virtual_address, variable_identifier)  ───►  Value: malloc(size)
```

```
                   [ APPLICATION HEAP ]              [ SHADOW HASH TABLE ]
                     ┌──────────────┐                 ┌───────────────────────┐
                     │ PgConnection │ (Addr: 0x7f10)  │ (0x7f10, 0x2001) ─────┼─► [ Extra Metrics ]
                     └──────┬───────┘                 └───────────────────────┘
                            │
              free(0x7f10)  │ (Connection terminates)
                            ▼
                     ┌──────────────┐                 ┌───────────────────────┐
                     │ [FREED HEAP] │                 │ (0x7f10, 0x2001) ─────┼─► [ LEAKED MEMORY! ]
                     └──────────────┘                 └───────────────────────┘
                                                       (Table retains dead entry forever)
```

### The Unbounded Memory Leak Vulnerability

A shadow variable registry introduces an inherent **lifecycle asymmetry**:
1. **Allocation**: When an object is created, the livepatched constructor calls:
   ```c
   ulp_shadow_alloc(obj_ptr, SHADOW_ID, sizeof(struct extra_data), init_data);
   ```
2. **Deallocation**: When the application destroys the object, the original code invokes `free(obj_ptr)` or Rust `drop()`.
3. **The Trap**: Because the original code knows nothing about the shadow table, **the shadow variable is never freed**.
   * In a long-running database or web server handling millions of requests, the shadow hash table leaks entries indefinitely, eventually causing an Out-Of-Memory (OOM) crash.

### The ABA / Address Reuse Hazard

An even more critical hazard than memory leaks is **Stale Pointer Aliasing (ABA)**:
1. Object A is allocated at virtual address `0x7f2000`. Shadow metadata is attached.
2. Object A is destroyed and returned to the heap allocator (glibc malloc / jemalloc).
3. The shadow table still contains an entry for `(0x7f2000, ID)`.
4. Sometime later, the allocator recycles address `0x7f2000` for a brand new Object B.
5. When the livepatch calls `ulp_shadow_get(0x7f2000, ID)`, **it receives Object A's stale, corrupt data!**

---

## 4. Mandatory Architectural Patterns for Shadow Variable Safety

To eliminate memory leaks and ABA hazards, livepatches must adhere to the following patterns:

### Pattern A: Rust RAII Destructor Binding (`Drop`)
In Rust systems (such as `pgrust`), shadow cleanup is guaranteed at compile time by binding to the `Drop` trait:

```rust
impl Drop for PgConnection {
    fn drop(&mut self) {
        unsafe {
            // Automatically unlinks and frees all shadow state upon struct drop
            self.shadow_clear_all();
        }
    }
}
```

### Pattern B: Dual-Hooking in C Daemons (Constructors + Destructors)
In C software (MariaDB, PostgreSQL, HAProxy), livepatches attaching shadow state **must hook both the constructor AND the destructor**:

```c
/* 1. Hook the object constructor / allocation path */
void *livepatch_connection_create(void)
{
    struct connection *conn = original_connection_create();
    if (conn) {
        struct shadow_state init = { .audit_id = get_next_audit_id() };
        ulp_shadow_alloc(conn, SHADOW_CONN_ID, sizeof(init), &init);
    }
    return conn;
}

/* 2. Hook the object destructor / free path (MANDATORY) */
void livepatch_connection_destroy(struct connection *conn)
{
    if (conn) {
        /* Unlink and free shadow allocation BEFORE freeing parent object */
        ulp_shadow_free(conn, SHADOW_CONN_ID);
    }
    original_connection_destroy(conn);
}
```

### Pattern C: Upstream Linux Kernel Livepatching Rule (`klp_shadow`)
This mirrors the official kernel policy defined in `Documentation/livepatch/shadow-vars.rst`:
> *"A shadow variable must be explicitly freed in the parent object's cleanup/free routine, or an unbounded leak and stale-pointer aliasing will occur."*

---

## 5. Summary of Driver Hardening Actions

In accordance with upstream hygiene and memory safety principles:
1. All instances of `strncpy()` in `ulp_driver.c` are converted to `strscpy()`.
2. Explicit `= 0` initializers on global static variables are removed.
3. The kernel module builds warning-free under upstream `checkpatch.pl`.
4. Shadow variable documentation is integrated into the livepatch developer SDK.
