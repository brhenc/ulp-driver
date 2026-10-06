# Safe Userspace Injection & Trampoline Engine

**Module:** Low-Level Userspace Injector  
**Source Path:** `ulp-driver/ulp_inject.c`, `ulp-driver/ulp_shadow.h`  
**Runtime Overhead:** $< 2\,\text{ms}$ Injection, $< 100\,\text{ns}$ Activation  

---

## 1. The Anatomy of Soft-Realtime Safe Injection

Traditional tools like GDB or standard ptrace injectors fail catastrophically when attached to high-throughput, multi-threaded server daemons under heavy query load (e.g. MariaDB with 50 worker threads or Go HTTP servers).

[`ulp-driver/ulp_inject.c`](/ulp-driver/ulp_inject.c) was designed to solve all four fundamental failure modes:

```
                    Target Thread Stack Layout During Injection
    High Memory
    ┌────────────────────────────────────────────────────────┐
    │ Active Stack Frames (MariaDB Worker / epoll_wait)      │
    │ [Local Variables, Saved RBP/RIP, Stack Canaries]       │
    ├────────────────────────────────────────────────────────┤ ◄── Original %rsp
    │ Red Zone (128 Bytes - Protected by System V ABI)       │
    ├────────────────────────────────────────────────────────┤
    │ Safety Margin (384 Bytes)                              │
    ├────────────────────────────────────────────────────────┤ ◄── Injected str_addr = (%rsp - 512) & ~0xF
    │ String: "/usr/lib/mysql/plugin/patch_v1.so\0"          │
    ├────────────────────────────────────────────────────────┤ ◄── ret_addr_ptr = str_addr - 8
    │ Gadget Pointer: Address of INT3 (0xCC) in libc.so.6    │
    └────────────────────────────────────────────────────────┘ ◄── Injected %rsp
    Low Memory
```

---

## 2. The 4 Critical Safeguards of `ulp_inject`

### 1. Red Zone & Stack Canary Evasion (`RSP - 512`)
Under the System V AMD64 ABI, compiler optimizations may use the 128-byte region below `%rsp` (the "red zone") without adjusting the stack pointer. 
* **The Hazard**: Pushing data directly onto `%rsp` clobbers active local variables or stack canaries (`-fstack-protector-strong`).
* **The Solution**: `ulp_inject` carves its execution frame at `(old_regs.rsp - 512) & ~0xF`, guaranteeing 16-byte alignment and complete clearance outside the red zone.

---

### 2. Neutralizing Kernel Syscall Rollback (`orig_rax = -1`)
When a thread is stopped while waiting on a restartable Linux syscall (e.g. `epoll_wait`, `poll`, `futex`), the Linux kernel's `ERESTARTSYS` logic automatically decrements `%rip` by 2 bytes upon resumption (to rewind over the `syscall` opcode `0x0F 0x05`).
* **The Hazard**: If `%rip` is redirected to `dlopen()` without clearing `orig_rax`, the kernel rolls back `%rip` by 2 bytes upon `PTRACE_CONT`, executing invalid misaligned instructions and triggering an immediate **`SIGILL` or `SIGSEGV`**.
* **The Solution**: `ulp_inject` explicitly sets `new_regs.orig_rax = -1`, informing the kernel that no syscall was interrupted.

---

### 3. Intel CET IBT & INT3 Gadget Return
Modern compilers enable Intel CET Indirect Branch Tracking (`-fcf-protection=full`).
* **The Hazard**: Pushing an arbitrary invalid return address onto the stack triggers an unhandled `SIGSEGV` or `SIGTRAP` crash when `dlopen()` executes `ret`.
* **The Solution**: `ulp_inject` scans the target's already-loaded `libc.so.6` text segment to locate an authentic native `0xCC` (`INT3`) opcode. When `dlopen` finishes and returns, it lands cleanly on the `INT3` gadget, raising a controlled `SIGTRAP` caught by `waitpid()`.

---

### 4. Non-Destructive FPU / AVX State Preservation
In addition to General Purpose Registers (`PTRACE_GETREGS`), `ulp_inject` snapshots the thread's complete floating point and vector register state (`PTRACE_GETFPREGS`), restoring all SIMD and SSE/AVX registers before detaching.

---

## 3. Dynamic DSO vs Static Binary Injection Modes

`ulp_inject` automatically detects whether the target executable is dynamic or statically linked:

```c
int is_dynamic = has_dynamic_libc(target_pid);

if (is_dynamic) {
    /* 1. Dynamic Mode: Injects shared library (.so) via libc dlopen() */
    uintptr_t remote_dlopen = get_remote_symbol(target_pid, "libc.so.6", "dlopen");
    ...
} else {
    /* 2. Static Binary Mode: Allocates executable page via remote sys_mmap */
    uintptr_t sys_gadget = get_remote_syscall_gadget(target_pid);
    uintptr_t mmap_addr = inject_static_payload(target_pid, code_bytes, len);
}
```

---

## 4. Shadow Variable Subsystem (`ulp_shadow.h`)

When livepatching daemons that pre-allocate fixed-size structs or arrays at startup (e.g. Percona `threads[max_connections]` or InnoDB 32-bit auto-increment counters), modifying the struct memory layout is impossible.

`ulp_shadow.h` provides an **in-memory, lockless striped RCU shadow registry**:

```
[In-Memory Daemon Object Pointer (e.g. TABLE* or THD*)] (Fixed memory layout)
                        │
                        ▼ (Pointer Address Tag)
[ULP Striped Hash Registry (256 Buckets)]
  └── Bucket Index: (obj_ptr ^ (field_id * GOLDEN_RATIO)) % 256
        └── Node: [ Key: obj_ptr | Field ID: 0x4001 | Dynamic 64-bit Shadow Variable ]
```

### Shadow API Reference:
* `void *ulp_shadow_alloc(void *obj, uint32_t id, size_t size, const void *init_data)`: Attaches dynamic shadow memory to an existing object pointer.
* `void *ulp_shadow_get(void *obj, uint32_t id)`: Retrieves the shadow variable in $< 15\,\text{ns}$ without acquiring global mutexes.
* `void ulp_shadow_free(void *obj, uint32_t id)`: Frees the shadow variable upon object destruction.
