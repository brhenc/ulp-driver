# ulp-driver

**ulp-driver** is a personal research project exploring **userspace livepatching (ULP)** on Linux: replacing functions inside running processes (C, Rust, Go) without restarting them. It consists of an x86_64 kernel driver, a ptrace-based injector, and a set of experiments against real daemons (HAProxy, PostgreSQL, MariaDB). There are also some kernel livepatching (KLP) samples.

The project was prototyped with AI to test whether the approach is feasible before investing serious time in it. If the results justify it, a full refactor into a proper long-term project will follow. Until then, the docs describe MVPs and overstate what the code does. See [Status & limitations](#status--limitations) for the current state.

---

## What's here

1. **ULP kernel driver** (`ulp-driver/`): a kernel module (x86_64) plus userspace tools (`ulp_ctl`, `ulp_inject`, `libulp_preload`). It writes function-entry trampolines into a target process, tracks applied patches, carries patches across `fork`/`exec`, and can hand its state over across module reloads.
2. **Injector** (`ulp_inject`): attaches with ptrace and loads a patch payload into the target, via `dlopen` for dynamic binaries or a remote `mmap` for static ones.
3. **Experiments**: multi-generation patching of one process, canary-style rollout (patching a fraction of requests), and trampoline encodings for other architectures tested under QEMU user-mode emulation.
4. **Signature tooling** (optional): `tools/ulp_crypto_verifier.py` checks patch payloads against a `policy.json` trust policy (cosign / GPG). It is a standalone pre-flight check and is not enforced by the driver or the injector.
5. **KLP samples** (`kernel-livepatch/`): small kernel livepatch modules.

---

## Status & limitations

- **Patch safety depends on the tool.** `ulp_ctl apply`/`revert` stop every thread of the target with ptrace and only write when no thread is inside the patch window (in testing, 300/300 apply+revert cycles on 8 threads hammering the patched function, where the previous approach crashed within 10). Tools that call the driver directly (`ulp_tui.py`, `libulp_preload`) do not stop threads yet, and the driver itself does not enforce it. A thread whose *return address* points into the first 16 bytes of the function (a call inside that window) is not detected.
- **Signatures are not enforced** on the injection path (see above).
- **No post-quantum signing yet.** An earlier experimental implementation was removed; a real one (liboqs or OpenSSL 3.5 ML-DSA) is on the TODO list.
- **`ulp_scope=1`** (same-UID access) checks matching credentials and refuses non-dumpable targets, but cannot apply Yama or LSM ptrace hooks (they are not exported to modules). Use the default root-only scope.
- **Emergency override is not authenticated in the kernel.** `ULP_IOC_SET_OVERRIDE` is accepted from any `CAP_SYS_ADMIN` caller that supplies the public magic constants in `ulp_uapi.h`; the kernel verifies no HMAC. The TTL is capped at 300 seconds (default 60). The HMAC-SHA256 override ticket (`/etc/ulp/override.ticket`, `/etc/ulp/hmac.key`) is made by `ulp_persist` and checked only in userspace by `libulp_preload`; it does not protect against root.
- **`state.bin` is trusted, not authenticated.** `/run/ulp/state.bin` is root-only and is read by the kernel only with `resume=1` (written only with `allow_resumption=1`). Fields are validated at restore (`tramp_len` must be 5 or 16, strings must be terminated), but there is no signature or HMAC.
- **Write restrictions.** The driver refuses to write into `VM_SHARED` mappings, the target must be a `VM_EXEC` mapping, and the VMA is re-checked immediately before the write.
- A security review and the follow-up work are tracked in [docs/SECURITY_AUDIT_PLAN.md](docs/SECURITY_AUDIT_PLAN.md).
- The driver is **x86_64 only**. The other-architecture work is limited to emulation tests.
- **Exec rules fire at the ELF entry point, not inside `execve()`.** Rules are armed with a uprobe on the binary's entry point (`uprobe_register` is exported by mainline, unlike `task_work_add`, so the module builds on Fedora and other vanilla kernels). The patch is written before the program's first instruction, after the dynamic loader has mapped the shared libraries. Rules are bound to the binary's inode when added: if the file is replaced, re-add the rule (persisted rules are re-armed by path at driver load).
- Benchmarks and test results were run on a small number of personal test VMs.

---

## Directory Structure

```
.
├── ulp-driver/            # Kernel driver, userspace tools, fuzzing harnesses
├── kernel-livepatch/      # Kernel livepatch modules (KLP samples, ULP-aware livepatch)
├── examples/              # Runnable end-to-end examples (C, Rust, driver reload)
├── docs/                  # Operator guide, hacking guides (docs/hacking/), design notes, writeups
├── signed-patches/        # Sample patch payloads with detached signatures (test keys)
├── ulp-keys/              # Public verification keys used by ulp-keys/policy.json
├── *-livepatch-bench/     # Livepatch benchmarks against HAProxy, PostgreSQL, MariaDB, Go, Rust
├── *-canary-bench/        # Canary-rollout and fault-handling experiments
├── cross-arch-bench/      # Trampoline encodings for other architectures (QEMU user-mode)
├── rust-livepatch-plugin/ # LLVM plugin for livepatchable Rust codegen
├── tests/                 # Integration test suites (run as root on a test VM)
├── scripts/dev-vm/        # Author's VM orchestration scripts (ssh/scp to named test VMs)
├── tools/                 # ulp_tui.py, ulp_crypto_verifier.py
├── patches/               # Upstream patches (rustc -Z patchable-function-entry)
├── telemetry/             # Prometheus exporter
└── vm-provisioning/       # Test VM provisioning script
```

See [`examples/README.md`](examples/README.md) for a guided walkthrough, [`docs/hacking/`](docs/hacking/README.md) for internals notes, and [`docs/OPERATOR_GUIDE.md`](docs/OPERATOR_GUIDE.md) for operating the driver.

---

## Quick start

### Requirements

- **x86_64 Linux 6.12 or newer** with `CONFIG_KPROBES` and `CONFIG_UPROBES` (standard distribution kernels have both). Tested on Debian 13 (6.12) and Fedora (7.2, 7.3-rc).
- **Headers for the running kernel**, gcc, make, the OpenSSL development package, and python3:
  ```bash
  apt install linux-headers-$(uname -r) build-essential libssl-dev python3
  ```
- **Root access**, on a disposable test machine or VM.
- **Secure Boot disabled**, or the module signed with an enrolled key. Otherwise `insmod` fails with `Key was rejected by service`.

### Build and load

```bash
make -C ulp-driver              # kernel module + ulp_ctl, ulp_inject, ulp_persist, libulp_preload.so
sudo insmod ulp-driver/ulp_driver.ko dev_mode=1
sudo make -C ulp-driver install # optional: tools to /usr/local, module to /lib/modules
```

### Run the first example

```bash
sudo examples/01_basic_c_service/run_example.sh
```

It starts a small service, injects a patch payload, redirects one function to it, and reverts it. [`examples/README.md`](examples/README.md) describes all the examples.

### Applying a patch by symbol

```bash
sudo ulp-driver/ulp_inject <pid> ./patch.so                         # load the patch library into the process
sudo ulp-driver/ulp_ctl apply <pid> /path/to/binary:func ./patch.so:new_func
sudo ulp-driver/ulp_ctl revert <pid> <target_hex_vaddr>             # address is printed by apply and ulp_ctl list
```

`ulp_ctl` resolves both symbols from the ELF symbol tables and `/proc/<pid>/maps` (PIE and non-PIE) and uses the function's real size. It refuses functions whose size is unknown or under 5 bytes. Functions under 16 bytes need the patch within ±2 GB, which is usually not the case for an injected library, so the driver rejects those.

### `dev_mode` and the maintenance window

By default the driver refuses to apply patches unless the calling file session has **armed a maintenance window** (`ULP_CMD_ARM`) and presents the current nonce. This applies equally to the ioctl path (`ULP_IOC_APPLY_PATCH`) and the `write()` command path (`ULP_CMD_APPLY_PATCH`); arming from one open file does not authorize another. `dev_mode=1` skips that check (and allows unloading the module and lowering `kernel.ulp_scope`), which is convenient for testing. Without `dev_mode`:

```bash
sudo ulp_ctl --arm=60 apply <pid> ...   # arm for this command only; relocks when ulp_ctl exits
sudo ulp_ctl arm 120                    # hold a window open for other tools until timeout or Ctrl-C
sudo ulp_ctl disarm
```

`kernel.ulp_scope` controls who may patch: 0 = disabled, 1 = same user, 2 = root only (default), 3 = root only and locked until reboot.

## Kernel Livepatching (KLP)

```bash
cd kernel-livepatch/
make

insmod livepatch_uname.ko
cat /proc/version
# Linux version 7.3.0-LIVEPATCHED ...

echo 0 > /sys/kernel/livepatch/livepatch_uname/enabled
rmmod livepatch_uname
```

---

## Signing Keys

Only **public** test keys are committed. Private signing keys are never stored in this repository; generate your own with `cosign generate-key-pair` or `gpg --gen-key` and point `ulp-keys/policy.json` at the corresponding public keys.

> **Warning:** This code loads a kernel module and modifies running processes. Use it only on disposable test machines.

---

## License

ulp-driver is licensed under the **GNU General Public License v2.0 only** (`GPL-2.0-only`), the same license as the Linux kernel. See [`LICENSE`](LICENSE). The following parts are licensed differently:

| Path | License |
|---|---|
| `ulp-driver/ulp_uapi.h` | `GPL-2.0-only WITH Linux-syscall-note` (userspace programs may include it without becoming GPL, as with kernel uapi headers) |
| `patches/rustc-patchable-function-entry.patch` | `MIT OR Apache-2.0` (matching the Rust compiler, for upstream submission) |
| `rust-livepatch-plugin/` | `Apache-2.0 WITH LLVM-exception` (matching LLVM) |

Full license and exception texts are in [`LICENSES/`](LICENSES/).
