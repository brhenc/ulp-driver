# ulp-driver: ULP Subsystem Operator Guide

**Subsystem**: Userspace Livepatching (ULP) for Linux  
**Target Systems**: Linux 6.x / 7.x (x86_64)  
**Document**: `docs/OPERATOR_GUIDE.md`  
**Status**: Official Operational & Reference Manual  

---

## 1. Subsystem Overview & Core Concepts

**ulp-driver** provides a high-assurance, in-kernel userspace livepatching subsystem (`ulp_driver.ko`) and userspace orchestration utilities (`ulp_ctl`, `ulp_inject`). It allows systems operators and site reliability engineers to hotpatch mission-critical server daemons (such as **HAProxy**, **MariaDB**, **PostgreSQL**, and **FRRouting**) in real time with **zero dropped connections, zero socket resets, and zero downtime**.

### Architectural Invariants

* **Autonomous Userspace Execution**: Once a trampoline is written into process memory, the CPU executes the replacement code directly in Ring 3 without issuing kernel transitions.
* **Driver Resumption**: The `ulp_driver` kernel module can be unloaded, upgraded, or reloaded while userspace processes remain fully patched. Active state is persisted to `/run/ulp/state.bin` and re-adopted automatically on driver reload.
* **CET / IBT Compliance**: Emits 16-byte CET/IBT-compliant absolute trampolines starting with `endbr64` (`0xf3 0x0f 0x1e 0xfa`) to prevent Indirect Branch Tracking faults.
* **Fail-Closed Security**: Controlled via sysctl scope ratchets (`/proc/sys/kernel/ulp_scope`) and strict memory validation (natural 8-byte alignment, thread quiescence checking, and futex state validation).

---

## 2. Kernel Module Configuration & Parameters

The driver is loaded via `insmod` or `modprobe`:

```bash
insmod ulp_driver.ko [dev_mode=1] [allow_resumption=1] [resume=1]
```

### Module Parameters Reference

| Parameter | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `dev_mode` | `bool` | `false` | Developer mode. Permits module unloading and scope relaxation in Scope 3 for testing and development environments. |
| `allow_resumption` | `bool` | `false` | **Zero-Downtime Module Reloading**. When set to `1`, unloading the module (`rmmod ulp_driver`) writes the active patch registry to `/run/ulp/state.bin` and leaves userspace trampolines intact. If set to `0`, unloading reverts all patches or rejects unload if patches are active. |
| `resume` | `bool` | `false` | **Automatic State Recovery**. When set to `1` during `insmod`, the driver scans `/run/ulp/state.bin`, validates memory trampolines against active process PIDs, and automatically re-adopts all patches into `/proc/ulp_patches`. |

### Sysctl Security Ratchet (`kernel.ulp_scope`)

Configure via `sysctl -w kernel.ulp_scope=<N>` or `/proc/sys/kernel/ulp_scope`:

| Scope Level | Mode Name | Operational Policy |
| :---: | :--- | :--- |
| **0** | `ULP_SCOPE_DISABLED` | Livepatching completely disabled. All new patch requests and execve rules are rejected. Emergency disarm state. |
| **1** | `ULP_SCOPE_USER_SAME_UID` | Non-root users may livepatch processes matching their own real UID. Cross-user and privilege escalation patching is blocked. |
| **2** | `ULP_SCOPE_ROOT_ONLY` *(Default)* | Only root (`CAP_SYS_ADMIN`) may inspect, apply, or revert livepatches. Standard production setting. |
| **3** | `ULP_SCOPE_LOCKED` | Immutable ratchet mode. Sysctl cannot be decreased without a reboot. Module unloading is permanently blocked unless `dev_mode=1`. |

---

## 3. CLI Command Reference

### 3.1 `ulp_ctl` — Livepatch Control Utility

Installed at `/usr/local/bin/ulp_ctl`. Interacts directly with the `/dev/ulp` character device.

#### 1. Applying a Livepatch
```bash
ulp_ctl apply <pid> <patch_name> <func_name> <target_hex_vaddr> <patch_hex_vaddr> [func_len] [futex_hex_vaddr]
```
* `<pid>`: Target process identifier.
* `<patch_name>`: Human-readable identifier for tracking (max 63 chars).
* `<func_name>`: Name of the function being intercepted (max 63 chars).
* `<target_hex_vaddr>`: Virtual address of the target function in the process address space. **Must be 8-byte aligned**.
* `<patch_hex_vaddr>`: Virtual address of the replacement function in the injected shared object.
* `[func_len]`: *(Optional)* Length of target function in bytes (defaults to 16). If `< 16`, the driver attempts a 5-byte relative jump (`ULP_TRAMP_REL5`). If `>= 16`, constructs a 16-byte CET absolute trampoline.
* `[futex_hex_vaddr]`: *(Optional)* Virtual address of an associated `uint32_t` futex. The driver verifies the futex is currently `0` (unlocked) before applying the patch.

#### 2. Reverting a Livepatch
```bash
ulp_ctl revert <pid> <target_hex_vaddr>
```
Restores the original 8/16 bytes preserved during patching and unregisters the entry from `/proc/ulp_patches`.

#### 3. Listing Active Patches
```bash
ulp_ctl list
```
Displays all livepatches registered with the kernel driver across all processes.

#### 4. Managing Persistent In-Kernel Startup Rules
Persistent rules allow the kernel to automatically intercept `execve()` calls matching a binary path and apply livepatches before userspace code begins running:

```bash
# Add a persistent startup rule
ulp_ctl add-rule <bin_path> <patch_name> <func_name> <target_offset_hex> <patch_vaddr_hex> [func_len] [match_uid] [global_scope]

# Delete a persistent startup rule
ulp_ctl del-rule <bin_path> <target_offset_hex>

# List all active startup rules
ulp_ctl list-rules
```
* *Special Behavior*: Setting `<patch_vaddr_hex>` to `0` automatically constructs an atomic return-zero stub (`endbr64; xor %eax, %eax; ret`), ideal for instantly disabling vulnerable subroutines or forcing security checks to pass.

#### 5. Emergency Override Token
```bash
# Temporarily bypass livepatching for a binary during incident response
ulp_ctl set-override <bin_path> [ttl_seconds]

# Clear active override
ulp_ctl clear-override
```

---

### 3.2 `ulp_inject` — Soft-Realtime Library Injector

Installed at `/usr/local/bin/ulp_inject`.

```bash
ulp_inject <pid> <path_to_so>
```
* Safely executes `dlopen()` on a private remote stack frame inside target PID.
* Injects and resolves the shared library in **under 2 milliseconds**.
* Preserves all general-purpose registers, floating-point state, and thread stack pointers.

---

## 4. End-to-End Operator Procedures

### Procedure A: Applying a Hotpatch to a Running Service

1. **Compile the Payload**:
   ```bash
   gcc -shared -fPIC -O2 -Wall -o /opt/patches/patch_service.so patch_service.c
   ```
2. **Inject the Library**:
   ```bash
   ulp_inject 12345 /opt/patches/patch_service.so
   ```
3. **Compute Function Addresses**:
   ```bash
   # Target address
   TARGET_VADDR=$(nm /usr/sbin/service | grep -w target_func | awk '{print "0x"$1}')

   # Patch address
   SO_BASE=$(grep "patch_service.so" /proc/12345/maps | head -n 1 | awk '{print $1}' | cut -d- -f1)
   SO_OFF=$(nm -D /opt/patches/patch_service.so | grep -w livepatch_func | awk '{print $1}')
   PATCH_VADDR=$(python3 -c "print(hex(0x$SO_BASE + 0x$SO_OFF))")
   ```
4. **Apply via `ulp_ctl`**:
   ```bash
   ulp_ctl apply 12345 secfix_001 target_func $TARGET_VADDR $PATCH_VADDR 16
   ```
5. **Verify in `/proc/ulp_patches`**:
   ```bash
   cat /proc/ulp_patches
   ```

---

### Procedure B: Upgrading the ULP Kernel Module with Zero Downtime

When `ulp_driver.ko` needs to be updated or upgraded for bugfixes or security maintenance:

1. **Verify Resumption is Enabled**:
   ```bash
   cat /sys/module/ulp_driver/parameters/allow_resumption
   # Must return 'Y'. If 'N', set:
   echo 1 > /sys/module/ulp_driver/parameters/allow_resumption
   ```

2. **Unload the Driver**:
   ```bash
   rmmod ulp_driver
   ```
   * The driver writes `/run/ulp/state.bin` containing all active patch descriptors and cryptographic hashes.
   * Userspace applications continue executing their hotpatches without any interruption.

3. **Verify State Snapshot**:
   ```bash
   ls -lh /run/ulp/state.bin
   ```

4. **Insert the New Driver Version**:
   ```bash
   insmod /path/to/new/ulp_driver.ko dev_mode=1 allow_resumption=1 resume=1
   ```
   * On initialization, the driver reads `/run/ulp/state.bin`.
   * It inspects each target PID, verifies the memory trampolines match original patch records, and re-adopts them into `/proc/ulp_patches`.

5. **Confirm Re-Adoption**:
   ```bash
   cat /proc/ulp_patches
   ```

---

## 5. Diagnostics & Troubleshooting

| Error Code | Error Message | Common Root Cause & Solution |
| :--- | :--- | :--- |
| **`-ESRCH`** | *Target PID not found* | Target process has exited or invalid PID provided. |
| **`-EINVAL`** | *Target address not 8-byte aligned* | Target function symbol does not start on an 8-byte boundary. Compile with `__attribute__((aligned(16)))`. |
| **`-ERANGE`** | *Relative jump displacement out of range* | Using 5-byte relative jump when target and patch are separated by > 2 GB. Use default 16-byte CET trampoline. |
| **`-EBUSY`** | *Cannot unload module* | Active livepatches present and `allow_resumption=0`. Either revert all patches or set `allow_resumption=1`. |
| **`-EPERM`** | *Operation not permitted* | Current user lacks privileges, sysctl scope is set to `0` (Disabled), or scope ratchet is set to `2` without root. |
| **`-EFAULT`** | *Bad address* | Target memory page is not mapped, or target process crashed during injection. Verify with `/proc/$PID/maps`. |
| **`-EAGAIN`** | *Thread not quiescent* | One or more threads in the target process have instruction pointers currently inside the function. Retry after load drops. |
| **`-EDEADLK`**| *Futex lock contention* | Specified futex is currently held by a thread (`val != 0`). Wait until lock is released before patching. |
