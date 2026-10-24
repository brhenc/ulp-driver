# ulp-driver Security Audit Plan

Status: working plan for the maintainers. First review: 2026-10-24.

This project is a prototype. The driver writes machine code into other processes from the kernel. Treat every item below as a requirement for any claim that the driver is safe to run on a machine that matters.

## 1. Scope and trust model

### What a caller can do

`/dev/ulp` lets a caller write a jump trampoline into the executable text of any process the driver's access check allows. That is equivalent to ptrace write access to that process: the caller can redirect any function in it, so it can run arbitrary code with the target's privileges. It can also add exec rules that do the same to every future run of a binary.

### Who can open it

The device node is mode 0600, owned by root. Operations additionally check `CAP_SYS_ADMIN` (`ulp_check_access`). There is no unprivileged interface in the default configuration.

### Module parameters

- `dev_mode` (default 0): skips the arming requirement for apply, allows module unload and lowering `kernel.ulp_scope` when it is 3. Testing only.
- `allow_resumption` (default 0): on unload, write the patch registry to `/run/ulp/state.bin` and leave trampolines in place.
- `resume` (default 0): on load, read `/run/ulp/state.bin` and re-adopt patches.

### Sysctl `kernel.ulp_scope`

- 0: disabled (root can still revert).
- 1: same UID. A non-root caller may patch processes with fully matching credentials that are dumpable. Yama and LSM ptrace hooks are not exported to modules and are NOT applied. This level is only reachable by an unprivileged user if an administrator relaxes the permissions of the device node, since the node is 0600 root by default.
- 2 (default): root only.
- 3: root only; the value cannot be lowered until reboot, and the module cannot be unloaded unless `dev_mode=1`.

### Kernel inputs

1. Eight ioctls (`ulp_uapi.h`): `ULP_IOC_APPLY_PATCH`, `REVERT_PATCH`, `LIST_PATCHES`, `ADD_RULE`, `DEL_RULE`, `LIST_RULES`, `SET_OVERRIDE`, `CLEAR_OVERRIDE`.
2. `write()` commands (`struct ulp_cmd_v1`, `copy_struct_from_user`): `ULP_CMD_ARM`, `DISARM`, `APPLY_PATCH`, `REVERT_PATCH`, `ADD_RULE`, `DEL_RULE`, `QUERY_STATUS`. `read()`/`poll()` return telemetry events.
3. The `kernel.ulp_scope` sysctl.
4. `/run/ulp/state.bin` (fallback `/run/ulp_state.bin`), parsed by `ulp_restore_state` when `resume=1`.
5. ELF headers of rule binaries, parsed at add-rule and restore time: the GNU build-id note (`ulp_read_build_id`), the entry point and `PT_LOAD` segments (`ulp_elf_parse`). The rule binary is whatever path the caller names, so its contents are attacker-influenced if a less-trusted user can write to or replace it.
6. A kprobe on `wake_up_new_task` (fork inheritance; runs in scheduler context) and a uprobe on each exec rule's binary entry point (runs in the new process's context).

### Trust levels

Root with `CAP_SYS_ADMIN` is trusted to do anything the driver can do; the goal is not to stop root from patching. The goals are: (a) a non-root user, or a compromised service, cannot reach any of the inputs above; (b) a malformed input supplied by root or found on disk (state file, rule binary, config) cannot crash or corrupt the kernel; (c) the documentation does not claim more than the code enforces.

## 2. Findings from the 2026-10-24 review

All fixed in this change except where noted.

1. Kernel stack overflow from an unvalidated `tramp_len` read from the state file in `ulp_restore_state`. Fixed: `tramp_len` must be 5 or 16.
2. Unterminated strings read from the state file. Fixed: every string field is forcibly NUL-terminated after each record is read, and `build_id_len` is bounds-checked.
3. Writes could reach `VM_SHARED` mappings, and the VMA was checked before, not at, the write. Fixed: `VM_SHARED` is refused, the target must be `VM_EXEC`, and the VMA is re-checked before the write.
4. The emergency override was documented as authenticated but the kernel checks only `CAP_SYS_ADMIN` and public magic constants; the TTL multiplication could overflow. Fixed: TTL capped at 300 seconds (default 60) and the documentation corrected. A kernel-side HMAC was deliberately not added: the key would be a root-owned file, so it would add nothing over `CAP_SYS_ADMIN`. The HMAC ticket remains a userspace-only check in `libulp_preload` and does not protect against root.
5. The ioctl and write apply paths used different gates. Fixed: both now require the caller's file session to have armed the driver with the current nonce (unless `dev_mode=1`); the bare `arm_nonce` bearer-token shortcut in the write path was removed. Consequence: `libulp_preload` arms its own fd for 5 seconds before applying, which replaces the global nonce and ends any window another session had open.
6. Known and documented, not fixed:
   - `ulp_scope=1` lacks Yama and LSM ptrace checks.
   - The in-kernel quiescence check is only accurate when userspace has stopped the threads. `ulp_ctl` does; `ulp_tui.py` and `libulp_preload` do not.
   - `dev_mode` bypasses arming.

## 3. Audit work plan

Do these in order. Each item has a deliverable; do not mark an item done without it.

### 3.1 State file as untrusted input

- Review `ulp_save_state` and `ulp_restore_state` end to end, assuming the file is arbitrary bytes (header, counts, every field, truncation, trailing data).
- Fuzz it in a VM: generate and mutate state files (a corpus from real `ulp_save_state` output plus bit flips, truncation, huge counts), load with `resume=1` under KASAN, record any splat.
- Consider an HMAC with a boot-time key. What it would buy: detection of modification by a process that can write `/run/ulp` but cannot read kernel memory or the key. What it would not buy: any protection against root, who can load modules or read the key source; and it does not help when the file is simply stale. Decide and write the decision down.
- Deliverable: fuzz harness in the repo, a list of fixed crashes, a written decision on the HMAC.

### 3.2 Untrusted-input inventory

- Produce a table: input, entry point, who can supply it, trust level, validation done, test coverage. Start with the six kernel inputs in section 1 and add the userspace inputs in 3.5.
- Build a malformed-ELF test set for `ulp_read_build_id` and `ulp_elf_parse`: truncated headers, huge `e_phnum`, `p_offset`/`p_filesz` beyond the file, overlapping or zero-length `PT_LOAD`, no `PT_LOAD` covering `e_entry`, 32-bit ELF, big-endian, note with oversized `namesz`/`descsz`, unterminated note name, build-id longer than 20 bytes, non-ELF files, files that shrink while being read.
- Run the set against add-rule and against restore, under KASAN.
- Deliverable: the inventory table (in this directory) and the test set with a script that runs it.

### 3.3 Memory-safety tooling

- Run on the Fedora debug kernel (lockdep, KASAN, KFENCE as available): `ulp-driver/test_concurrent_ioctls`, `ulp-driver/syz_coverage_fuzzer`, and the examples.
- Extend the existing `ulp-driver/ulp.syz` into a full syzkaller description for `/dev/ulp` (all eight ioctls and every `ULP_CMD_*` through `write()`), and run syzkaller against it.
- Add `sparse` (`C=2`) and `smatch` targets to `ulp-driver/Makefile`.
- Deliverable: clean runs (or a bug list), the syzkaller description, the Makefile targets.

### 3.4 Policy boundary review

- Compare `ulp_check_access` with the kernel's `ptrace_may_access`/`__ptrace_may_access` line by line and list each check that is missing in the module (Yama, LSM hooks, user namespace and `ptrace` capability checks, dumpable rules).
- Decide whether `ulp_scope=1` should exist at all. If it stays, document precisely which checks are absent; if it goes, remove it from the sysctl range and the docs.
- Check that revert and list paths cannot be used to learn about or touch processes the caller could not patch.
- Deliverable: a written comparison and a decision.

### 3.5 Root-run userspace

- `ulp_persist.c` reads `/etc/ulp/*.conf` as root: bounds-check every `fgets`/`sscanf` use, field widths, numeric conversions, and the lines that become `ulp_kernel_rule_req`.
- Review `ulp_inject.c`'s use of ptrace (register save/restore, stack placement, handling of a target that changes state mid-injection).
- Determine who can write `/etc/ulp` and `/run/ulp`, and the modes and ownership the tools create them with. Anyone who can write the configs or the HMAC key can cause root to add rules or forge override tickets.
- Deliverable: patches or issues for each finding, and a stated permission requirement for `/etc/ulp`.

### 3.6 Documentation honesty check (recurring)

Before each release and after any security-relevant change, grep the docs for claims about authentication, signing, HMAC, fail-closed behaviour and arming, and compare each with the code:

```
grep -rn -i "override\|hmac\|ticket\|signed\|authenticat\|fail-closed" \
  --include=*.md --include=*.typ --include=ulp_uapi.h .
```

Deliverable: a short note in the release checklist that this was done and by whom.

## 4. Re-running the checks

Build against the host's kernel headers:

```
make -C ulp-driver
```

Style check on the driver (from a kernel tree):

```
linux/scripts/checkpatch.pl --no-tree --strict -f ulp-driver/ulp_driver.c
```

VM test, on a Fedora debug kernel and on Debian 13. Load the module, then run the exec-rule example with the freshly built tool:

```
sudo insmod ulp-driver/ulp_driver.ko
ULP_CTL=$PWD/ulp-driver/ulp_ctl sudo -E examples/04_exec_rule_persistence/run_example.sh
```

Add `dev_mode=1` to `insmod` only for tests that do not exercise arming. Check `dmesg` for KASAN, lockdep or warning output after each run. Concurrency and fuzz runs: `ulp-driver/test_concurrent_ioctls` and `ulp-driver/syz_coverage_fuzzer` on the debug kernel.
