# ulp-driver

**ulp-driver** is a personal research project exploring **userspace livepatching (ULP)** on Linux: replacing functions inside running processes (C, Rust, Go) without restarting them. It consists of an x86_64 kernel driver, a ptrace-based injector, and a set of experiments against real daemons (HAProxy, PostgreSQL, MariaDB). There are also some kernel livepatching (KLP) samples.

The project was prototyped with AI to test whether the approach is feasible before investing serious time in it. If the results justify it, a full refactor into a proper long-term project will follow. Until then, the docs describe MVPs and overstate what the code does. See [Status & limitations](#status--limitations) for the current state.

---

## What's here

1. **ULP kernel driver** (`ulp-driver/`): a kernel module (x86_64) plus userspace tools (`ulp_ctl`, `ulp_inject`, `libulp_preload`). It writes function-entry trampolines into a target process, tracks applied patches, carries patches across `fork`/`exec`, and can hand its state over across module reloads.
2. **Injector** (`ulp_inject`): attaches with ptrace and loads a patch payload into the target, via `dlopen` for dynamic binaries or a remote `mmap` for static ones.
3. **Experiments**: multi-generation patching of one process, canary-style rollout (patching a fraction of requests), and trampoline encodings for other architectures tested under QEMU user-mode emulation.
4. **Signature tooling** (optional): `ulp_crypto_verifier.py` checks patch payloads against a `policy.json` trust policy (cosign / GPG). It is a standalone pre-flight check and is not enforced by the driver or the injector.
5. **KLP samples** (`kernel-livepatch/`): small kernel livepatch modules.

---

## Status & limitations

- **Patch application is best-effort, not atomic.** The driver writes trampolines with `access_process_vm()` without stopping the target's threads. The quiescence check (no thread executing in the patched range) inspects saved register state and is racy for threads running at the time. A thread can occasionally execute a partially written trampoline.
- **Signatures are not enforced** on the injection path (see above).
- **The post-quantum signing (`ulp_pqc_signer.py`) is a toy.** It is a Dilithium-style learning implementation, not FIPS 204 ML-DSA. It does not interoperate with real ML-DSA libraries and must not be used for anything security-relevant.
- **`ulp_scope=1`** (same-UID access) checks matching credentials and refuses non-dumpable targets, but cannot apply Yama or LSM ptrace hooks (they are not exported to modules). Use the default root-only scope.
- The driver is **x86_64 only**. The other-architecture work is limited to emulation tests.
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
├── ulp-keys/              # Public verification keys used by policy.json
├── *-livepatch-bench/     # Livepatch benchmarks against HAProxy, PostgreSQL, MariaDB, Go, Rust
├── *-canary-bench/        # Canary-rollout and fault-handling experiments
├── cross-arch-bench/      # Trampoline encodings for other architectures (QEMU user-mode)
├── rust-livepatch-plugin/ # LLVM plugin for livepatchable Rust codegen
├── telemetry/             # Prometheus exporter
└── vm-provisioning/       # Test VM provisioning script
```

See [`examples/README.md`](examples/README.md) for a guided walkthrough, [`docs/hacking/`](docs/hacking/README.md) for internals notes, and [`docs/OPERATOR_GUIDE.md`](docs/OPERATOR_GUIDE.md) for operating the driver.

---

## Building the ULP Driver

```bash
cd ulp-driver/
make
insmod ulp_driver.ko dev_mode=1
```

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

Only **public** test keys are committed. Private signing keys are never stored in this repository; generate your own with `cosign generate-key-pair` or `gpg --gen-key` and point `policy.json` at the corresponding public keys.

> **Warning:** This code loads a kernel module and modifies running processes. Use it only on disposable test machines.

---

## License

ulp-driver is licensed under the **GNU General Public License v2.0 only** (`GPL-2.0-only`), the same license as the Linux kernel. See [`LICENSE`](LICENSE). The following parts are licensed differently:

| Path | License |
|---|---|
| `ulp-driver/ulp_uapi.h` | `GPL-2.0-only WITH Linux-syscall-note` (userspace programs may include it without becoming GPL, as with kernel uapi headers) |
| `upstream.patch` | `MIT OR Apache-2.0` (matching the Rust compiler, for upstream submission) |
| `rust-livepatch-plugin/` | `Apache-2.0 WITH LLVM-exception` (matching LLVM) |

Full license and exception texts are in [`LICENSES/`](LICENSES/).
