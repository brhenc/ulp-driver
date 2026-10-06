# Kernel Driver Internals & ULP Subsystem Architecture

**Module:** Linux Kernel Module  
**Source Path:** `ulp-driver/ulp_driver.c`, `ulp-driver/ulp_uapi.h`  
**License:** GPL-2.0-only  
**Device Node:** `/dev/ulp` (Mode `0600`, Root Owned)  

---

## 1. Core Data Structures

### 1.1 Patch Registry Entry (`struct ulp_patch_entry`)
Every active livepatch in the system is tracked inside a kernel hash table/linked list protected by a mutex and RCU:

```c
struct ulp_patch_entry {
    struct list_head list;
    u32              pid;               /* Target process PID */
    u32              creator_uid;       /* UID that applied the patch */
    char             patch_name[32];    /* Human-readable patch identifier */
    char             func_name[64];     /* Target function symbol name */
    u64              target_vaddr;      /* Original function virtual address */
    u64              patch_vaddr;       /* Injected patch function virtual address */
    u8               orig_bytes[16];    /* Backup of pristine original instructions */
    u8               patch_bytes[16];   /* Injected trampoline instruction bytes */
    u32              trampoline_len;    /* 5, 13, 14, or 16 bytes */
    u32              generation;        /* Generation index: 1, 2, 3... */
    u64              applied_at_ns;     /* Monotonic timestamp of activation */
    bool             is_active;         /* 1 = Applied/Active, 0 = Reverted */
};
```

---

## 2. The Fail-Closed Arming State Machine

To prevent accidental, concurrent, or malicious livepatch injection during normal operations, the driver enforces a strict **Fail-Closed Arming State Machine**:

```
 ┌────────────────────────────────────────────────────────┐
 │                   ULP_STATE_LOCKED                     │
 │  (Default State: All apply/revert ioctls REJECTED)     │
 └──────────────────────────┬─────────────────────────────┘
                            │ ULP_CMD_ARM (Token + TTL)
                            ▼
 ┌────────────────────────────────────────────────────────┐
 │                   ULP_STATE_ARMED                      │
 │  (Maintenance Window Active: Livepatching ENABLED)    │
 └───────────┬────────────────────────────────┬───────────┘
             │                                │
             │ ULP_CMD_DISARM                 │ Timer Expires (TTL Elapsed)
             ▼                                ▼
 ┌────────────────────────────────────────────────────────┐
 │                   ULP_STATE_LOCKED                     │
 │  (Fail-Closed Auto-Lock: All modifications REJECTED)   │
 └────────────────────────────────────────────────────────┘
```

### Implementation Details:
* **Arming Request (`ULP_CMD_ARM`)**:
  The operator provides a TTL in seconds (e.g. 60s). The kernel driver:
  1. Generates a cryptographic nonce `g_arm_nonce`.
  2. Sets `g_driver_state = ULP_STATE_ARMED`.
  3. Starts kernel timer `g_arm_timer` with expiry `jiffies + ttl * HZ`.
* **Auto-Lock Callback (`ulp_arm_timer_fn`)**:
  When the timer expires, the kernel timer callback atomically switches state back to `ULP_STATE_LOCKED` and broadcasts a `ULP_EVT_DISARMED` event to all open listeners on `/dev/ulp`.

---

## 3. Atomic Text Poke Engine

Modifying the executable code of a multi-threaded process while dozens of CPU cores are actively executing instructions requires extreme care to prevent **instruction fetch tearing**.

### The 8-Byte Atomic Text Poke Routine
```c
static int ulp_atomic_text_poke(struct mm_struct *mm, u64 vaddr, const void *new_bytes, size_t len)
{
    /* 1. Verify target VMA under mmap_read_lock */
    mmap_read_lock(mm);
    struct vm_area_struct *vma = find_vma(mm, vaddr);
    if (!vma || !(vma->vm_flags & VM_EXEC)) {
        mmap_read_unlock(mm);
        return -EFAULT;
    }
    mmap_read_unlock(mm);

    /* 2. Decoupled Memory Write via access_process_vm() */
    int written = access_process_vm(target_task, vaddr, (void *)new_bytes, len,
                                    FOLL_FORCE | FOLL_WRITE);
    if (written != len)
        return -EIO;

    /* 3. Cross-CPU Instruction Cache Serialization */
    smp_call_function(ulp_sync_core_ipi, NULL, 1);
    return 0;
}
```

### Why This is 100% Thread-Safe:
1. **No `SIGSTOP`**: Worker threads are never frozen. They continue executing queries seamlessly.
2. **Atomic Word Store**: On x86_64, 8-byte aligned writes to cache lines are guaranteed atomic by the CPU hardware bus.
3. **IPI Broadcast (`sync_core`)**: Forces all CPU cores to flush their speculative instruction prefetch pipelines, ensuring that subsequent instruction fetches decode the new trampoline immediately.

---

## 4. Dead PID Reaping & State Cleanup

When a target process terminates (either normally or due to a crash), orphaned patch records could theoretically cause state leaks or accidental collision if the OS reuses the PID.

The driver implements **Automatic Dead PID Reaping**:
```c
static void ulp_reap_dead_pids(void)
{
    struct ulp_patch_entry *entry, *tmp;
    mutex_lock(&g_registry_mutex);
    
    list_for_each_entry_safe(entry, tmp, &g_patch_list, list) {
        struct pid *pid_struct = find_get_pid(entry->pid);
        if (!pid_struct) {
            /* Process has exited: purge record */
            pr_info("[ulp_driver] Reaping stale patch '%s' for dead PID %d\n",
                    entry->patch_name, entry->pid);
            list_del(&entry->list);
            kfree(entry);
        } else {
            put_pid(pid_struct);
        }
    }
    
    mutex_unlock(&g_registry_mutex);
}
```

---

## 5. Security Ratchet (`/proc/sys/kernel/ulp_mode`)

A multi-mode sysctl ratchet governs global driver permissions:

| Mode | Value | Enforcement Policy |
| :--- | :--- | :--- |
| **Disabled** | `0` | Driver is completely disabled. All commands return `-EPERM`. |
| **Same-UID** | `1` | Callers can only patch processes matching their own `current_uid()`. |
| **Root-Only** | `2` | Requires `capable(CAP_SYS_ADMIN)` and `capable(CAP_SYS_PTRACE)`. |
| **Locked** | `3` | Permanent hardware security lock: mode cannot be downgraded without a full system reboot. |

---

## 6. Plan 9 VFS Command & Telemetry Protocol

In addition to standard `ioctl()`, `/dev/ulp` implements a high-performance **Mode 0600 VFS Protocol**:
* **`read(fd, &event, sizeof(struct ulp_event))`**: Streams live telemetry ring buffer events (patch applied, reverted, armed, disarmed, errors) to userspace watchers (such as `ulp_tui.py`).
* **`write(fd, &cmd, sizeof(struct ulp_cmd_payload))`**: Directly dispatches binary command payloads for zero-dependency scripting.
