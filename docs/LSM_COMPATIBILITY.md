# Linux Security Module (LSM) Compatibility & Architecture Guide

**ulp-driver: Userspace Livepatching (ULP) Security Framework**  
**Document**: `docs/LSM_COMPATIBILITY.md`  
**Status**: Production Specification  
**Kernel Target**: Linux 6.x / 7.x (Debian 13, RHEL 9/10, Fedora, Ubuntu)

---

## 1. Executive Summary

The ulp-driver Userspace Livepatching (ULP) subsystem operates across two privilege layers:
1. **The Kernel Control Plane (`ulp_driver.ko`, `/dev/ulp`, sysfs)**: Registers kprobes, verifies permissions, manages state serialization, and atomically modifies userspace text pages.
2. **The Userspace Data Plane (`pgrust`, `mariadbd`, `postgres`, `haproxy`)**: Executes modified code paths via atomic trampolines (`E9 rel32` or 16-byte CET/IBT absolute jumps) without kernel intervention during active execution.

In modern Linux distributions, Discretionary Access Control (DAC) is superseded by the **Linux Security Module (LSM)** framework. In standard Debian 13 and enterprise distributions, the active LSM stack includes:
```text
lockdown, capability, landlock, yama, apparmor, selinux, bpf, ipe, ima, evm
```

This document specifies how `ulp_driver` interfaces with each active security module, details the required policy configurations, analyzes the security of the resumption state file (`/run/ulp/state.bin`), and provides reference policy implementations for SELinux and AppArmor.

---

## 2. Core LSM Interaction Points

`ulp_driver` interacts with the LSM framework at three distinct boundaries:

```
                                  [ LSM INTEGRATION BOUNDARIES ]
                                                │
         ┌──────────────────────────────────────┼──────────────────────────────────────┐
         ▼                                      ▼                                      ▼
[ 1. Device Node: /dev/ulp ]        [ 2. Memory Text Poke ]                [ 3. Resumption State ]
  • File class: chr_file              • access_process_vm()                  • File: /run/ulp/state.bin
  • security_file_open()              • check_mem_permission()               • Mode: 0600 (root:root)
  • security_file_ioctl()             • security_ptrace_access_check()       • In-memory signature check
  • SELinux: ulp_device_t             • SELinux: allow admin target:ptrace   • SELinux: ulp_runtime_t
```

### Boundary 1: Device Node Access (`/dev/ulp`)
* **Operation**: An operator or orchestration agent (`ulp_ctl`, `ulp_inject`, `ulp_persist`) opens `/dev/ulp` and issues ioctl commands (`ULP_IOC_APPLY_PATCH`, `ULP_IOC_REVERT_PATCH`).
* **LSM Hooks Triggered**:
  - `security_file_open()`
  - `security_file_ioctl()`
  - `security_file_read()` (VFS telemetry stream)
  - `security_file_write()` (Plan 9 VFS command stream)
* **DAC Enforcement**: Mode `0600` (`crw------- root:root`).
* **MAC Enforcement**: Must be labeled with a distinct device type (`ulp_device_t`). Only authorized administrative domains are granted access.

### Boundary 2: Cross-Process Memory Poke (`access_process_vm`)
* **Operation**: When activating or reverting a livepatch, `ulp_driver.c` calls `access_process_vm(task, target_vaddr, patch_bytes, len, FOLL_FORCE | FOLL_WRITE)`.
* **LSM Hooks Triggered**:
  - Inside the kernel, `access_process_vm()` calls `check_mem_permission(task)`.
  - `check_mem_permission()` invokes:
    ```c
    security_ptrace_access_check(task, PTRACE_MODE_ATTACH_FSCREDS);
    ```
* **LSM Behavior by Module**:
  - **SELinux**: Checks if the calling domain has permission to `ptrace` the target process's domain (`allow <source_domain> <target_domain>:process ptrace;`).
  - **AppArmor**: Checks if the tracer's profile has `ptrace (trace, read)` permission targeting the tracee's profile.
  - **Yama (`/proc/sys/kernel/yama/ptrace_scope`)**:
    * Scope 0 (Classic): Normal DAC/capability rules apply.
    * Scope 1 (Restricted): Non-child processes require `CAP_SYS_PTRACE`.
    * Scope 2 (Admin-Only): Only processes with `CAP_SYS_PTRACE` can attach.
    * Scope 3 (Locked): No process can attach via ptrace; reboots required to unlock.
* **Why `FOLL_FORCE` Does Not Violate W^X (Write XOR Execute)**:
  `access_process_vm()` resolves the virtual address to physical pages via `get_user_pages_remote(FOLL_FORCE)`. The kernel maps the physical page into kernel address space via `kmap_local_page()`, writes the 5-byte or 16-byte trampoline, and serializes the pipeline using `flush_icache_range()` / IPI core syncs. Because userspace `mprotect(PROT_WRITE)` is never called, SELinux `execmem` and `execmod` rules are not violated.

### Boundary 3: Resumption State File (`/run/ulp/state.bin`)
* **Operation**: When `ulp_driver.ko` is unloaded with `allow_resumption=1`, `ulp_save_state()` creates `/run/ulp/state.bin` via `filp_open()`. When reloaded with `resume=1`, `ulp_restore_state()` parses the snapshot.
* **LSM Hooks Triggered**:
  - `security_file_open()`
  - `security_file_permission()`
  - `security_inode_create()` / `security_inode_unlink()`
* **Tamper-Resistance Analysis**:
  - **DAC Protection**: Mode `0600` root-only permissions in `/run/ulp/` (RAM-backed `tmpfs`).
  - **Anti-Injection Invariant**: `ulp_restore_state()` inspects running processes and verifies that memory at `target_vaddr` already matches `prec.patch_bytes`. An attacker cannot inject arbitrary code by altering `state.bin`.
  - **Rollback Hardening**: An attacker with root could alter `orig_bytes`, leading to corrupted rollback when running `ulp_ctl revert`. To prevent this, `state.bin` should be protected by SELinux type enforcement (`ulp_runtime_t`) and in-kernel HMAC verification.

---

## 3. SELinux Reference Policy Specification

To deploy `ulp_driver` under SELinux in `enforcing` mode, compile and load the following policy module.

### A. Type Enforcement (`ulp.te`)
```te
policy_module(ulp, 1.0.0)

gen_require(`
    attribute domain;
    type unconfined_t;
    type sysadm_t;
    type init_t;
')

# Types defined by ULP
type ulp_t;
type ulp_exec_t;
type ulp_device_t;
type ulp_runtime_t;

# Device and File designations
dev_node(ulp_device_t)
files_type(ulp_runtime_t)

# Allow admin roles to manage /dev/ulp
allow sysadm_t ulp_device_t:chr_file { open read write ioctl getattr };
allow unconfined_t ulp_device_t:chr_file { open read write ioctl getattr };

# Allow state management in /run/ulp/
allow sysadm_t ulp_runtime_t:dir { create_dir_perms mounton };
allow sysadm_t ulp_runtime_t:file { create_file_perms };
allow unconfined_t ulp_runtime_t:dir { create_dir_perms };
allow unconfined_t ulp_runtime_t:file { create_file_perms };

# Kernel driver context for kthreads / state recovery
allow init_t ulp_runtime_t:dir { read search write add_name remove_name };
allow init_t ulp_runtime_t:file { read write open getattr unlink };
```

### B. Interface Definitions (`ulp.if`)
```te
## <summary>ulp-driver Userspace Livepatching Policy Interface</summary>

interface(`ulp_admin_domain', `
    gen_require(`
        type $1;
        type ulp_device_t;
        type ulp_runtime_t;
    ')
    allow $1 ulp_device_t:chr_file rw_file_perms;
    allow $1 ulp_runtime_t:dir rw_dir_perms;
    allow $1 ulp_runtime_t:file rw_file_perms;
')

interface(`ulp_patchable_domain', `
    gen_require(`
        type $1;
        type sysadm_t;
    ')
    # Grant ptrace inspection and poke permission to livepatch admin
    allow sysadm_t $1:process { ptrace getattr signull };
')
```

### C. File Contexts (`ulp.fc`)
```te
/dev/ulp                -- gen_context(system_u:object_r:ulp_device_t,s0)
/usr/local/bin/ulp_ctl  -- gen_context(system_u:object_r:ulp_exec_t,s0)
/run/ulp(/.*)?             gen_context(system_u:object_r:ulp_runtime_t,s0)
```

### D. Enabling Confined Target Services
To livepatch confined daemons, grant the `ulp_patchable_domain` interface for each target:
```te
# In target service policy additions:
ulp_patchable_domain(mysqld_t)
ulp_patchable_domain(postgresql_t)
ulp_patchable_domain(haproxy_t)
```

---

## 4. AppArmor Profile Configuration

AppArmor uses path-based access control and mediation of `ptrace` pairs. When target processes are confined by AppArmor, the livepatching controller and target profiles must permit cross-profile ptrace.

### Target Daemon Rules (e.g. `/etc/apparmor.d/usr.sbin.mariadbd`)
Add the following permissions to allow `ulp_driver` and administrative tools to inspect and attach to `mariadbd`:
```apparmor
# ulp-driver ULP livepatching support
ptrace (read, trace) peer=unconfined,
ptrace (read, trace) peer=/usr/local/bin/ulp_ctl,
ptrace (read, trace) peer=/usr/local/bin/ulp_inject,

# Allow loading preloaded or injected livepatch shared objects
/usr/lib/mysql/plugin/patch_*.so mr,
/var/lib/ulp/patches/*.so mr,
```

### Administrative Tool Profile (`/etc/apparmor.d/usr.local.bin.ulp_ctl`)
```apparmor
#include <tunables/global>

/usr/local/bin/ulp_ctl {
  #include <abstractions/base>

  capability sys_admin,
  capability sys_ptrace,

  # Access to ULP device and state
  /dev/ulp rw,
  /proc/ulp_patches r,
  /run/ulp/ rw,
  /run/ulp/** rw,

  # Target inspection
  /proc/*/maps r,
  /proc/*/status r,
  /proc/*/cmdline r,

  # Grant ptrace access to target profiles
  ptrace (trace) peer=**,
}
```

---

## 5. Linux Yama & Capability Requirements

The `yama` LSM specifically controls ptrace security boundaries.

### Yama Scopes & ULP Operations:
* **Scope 0 (`yama.ptrace_scope = 0`)**:
  Standard Linux permissions. `ulp_ctl` and `ulp_driver` succeed as long as caller is root or same UID (Scope 1 mode).
* **Scope 1 (`yama.ptrace_scope = 1`) [Ubuntu/Debian Default]**:
  Only parent processes can attach to children. Since `mariadbd` or `postgres` are not children of `ulp_ctl`, callers require `CAP_SYS_PTRACE`.
* **Scope 2 (`yama.ptrace_scope = 2`) [Hardened Server]**:
  Only processes with `CAP_SYS_PTRACE` can inspect other processes. `ulp_ctl` running as root possesses `CAP_SYS_PTRACE` and functions normally.
* **Scope 3 (`yama.ptrace_scope = 3`) [Lockdown]**:
  No process may invoke ptrace system calls.
  - **Impact**: Userspace `ulp_inject` (which uses ptrace to inject `.so` stubs) is **blocked**.
  - **Bypass / Native Path**: In-kernel livepatching (`ulp_driver` direct poke) and `libulp_preload.so` via `/etc/ld.so.preload` **continue to function**, because `libulp_preload.so` is loaded by the dynamic linker at execve time without using ptrace.

---

## 6. Real-Time LSM Context Auditing in `ulp_driver`

`ulp_driver` includes Plan 9 VFS telemetry streaming (`/dev/ulp` read). To capture the exact security context of the user or script initiating a patch, `ulp_driver.c` integrates with LSM audit helpers:

```c
#include <linux/security.h>

static void ulp_audit_security_context(struct ulp_event *ev)
{
    u32 secid;
    char *secctx = NULL;
    u32 seclen = 0;

    security_task_getsecid(current, &secid);
    if (security_secid_to_secctx(secid, &secctx, &seclen) == 0) {
        /* Record first 31 chars of security context into event log */
        strncpy(ev->msg, secctx, sizeof(ev->msg) - 1);
        security_release_secctx(secctx, seclen);
    } else {
        snprintf(ev->msg, sizeof(ev->msg), "secid=%u", secid);
    }
}
```
When an event (`ULP_EVT_MANUAL_APPLY`, `ULP_EVT_RESUME`, `ULP_EVT_MANUAL_REVERT`) is logged, the telemetry record includes the caller's active SELinux context (e.g., `system_u:system_r:sysadm_t:s0`), providing non-repudiation audit trails for compliance.

---

## 7. Troubleshooting LSM Denials

### Identifying SELinux AVC Denials:
```bash
# Check audit log for ULP or ptrace denials
ausearch -m AVC -ts recent | grep -E 'ulp|ptrace'

# Generate suggested policy rules from denials
ausearch -m AVC -ts recent | audit2allow -m ulp_fixes > ulp_fixes.te
```

### Identifying AppArmor Denials:
```bash
# View kernel AppArmor audit messages
dmesg | grep -E 'apparmor.*DENIED.*(ulp|ptrace)'

# Or via journalctl
journalctl -k -g 'apparmor="DENIED"'
```

---

## 8. Summary of Security Matrix

| Security Layer | Default Behavior | Required Configuration for ULP |
| :--- | :--- | :--- |
| **Linux DAC** | Mode `0600` on `/dev/ulp` and `/run/ulp/state.bin` | Root / `CAP_SYS_ADMIN` required |
| **Yama Ptrace** | Restricted (`scope >= 1`) | Requires `CAP_SYS_PTRACE` for `ulp_ctl` / `ulp_inject` |
| **SELinux** | Blocks ptrace across domain boundaries | Deploy `ulp.te` policy; add `ulp_patchable_domain(<target>)` |
| **AppArmor** | Blocks cross-profile ptrace | Add `ptrace (trace) peer=...` to target profiles |
| **W^X / MPROTECT** | Banned `RWX` memory allocations | Fully compliant (`FOLL_FORCE` physical page write avoids `mprotect`) |
| **Resumption State** | Re-adopts memory-verified trampolines | Tamper-proof against code injection; protected via DAC `0600` + `ulp_runtime_t` |
