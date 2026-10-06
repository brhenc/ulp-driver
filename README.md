# ulp-driver

**ulp-driver** is an experimental research project for **Zero-Downtime Userspace Livepatching (ULP)** on Linux, backed by a kernel driver, alongside **Kernel Livepatching (KLP)** experiments. It patches functions inside running processes (C, Rust, Go) without restarts, dropped sockets, or lost in-memory state, across x86_64, arm64, riscv64, s390x, ppc64le and loongarch64.

---

## Architecture Overview

1. **ULP kernel driver** (`ulp-driver/`): a kernel module plus userspace tooling (`ulp_ctl`, `ulp_inject`, `libulp_preload`) that injects signed patch payloads into live processes, installs function trampolines, and supports shadow variables, exec-rule persistence, and driver resumption / state handoff across module reloads.
2. **Linux Kernel 7.x Livepatching**: scheduler-assisted transition convergence (`linux/livepatch_sched.h`), architecture-aware syscall wrappers (`KLP_SYSCALL_DEFINEx`), and static call trampolines (`KLP_STATIC_CALL`).
3. **Patch signing & policy**: patch payloads are verified against a `policy.json` trust policy (Sigstore/cosign, GPG, and hybrid post-quantum ML-DSA-65 signatures) before injection.
4. **Continuous & canary livepatching**: multi-generation patch stacks on a single process, statistical canary rollout (e.g. 1% of requests), and crash-resilient fallback.

---

## Directory Structure

```
.
├── ulp-driver/            # Kernel driver, userspace tools, fuzzing harnesses
├── kernel-livepatch/      # Kernel livepatch modules (KLP samples, ULP-aware livepatch)
├── examples/              # Runnable end-to-end examples (C, Rust, zero-downtime resumption)
├── docs/                  # Operator guide, hacking guides (docs/hacking/), design notes, writeups
├── signed-patches/        # Sample patch payloads with detached signatures
├── ulp-keys/              # Public verification keys used by policy.json
├── *-livepatch-bench/     # Livepatch benchmarks against HAProxy, PostgreSQL, MariaDB, Go, Rust
├── *-canary-bench/        # Canary livepatching and fault-resilience suites
├── cross-arch-bench/      # Multi-architecture trampoline emulation suite
├── rust-livepatch-plugin/ # LLVM plugin for livepatchable Rust codegen
├── telemetry/             # Prometheus exporter
└── vm-provisioning/       # Test VM provisioning script
```

See [`examples/README.md`](examples/README.md) for a guided walkthrough, [`docs/hacking/`](docs/hacking/README.md) for in-depth internals, and [`docs/OPERATOR_GUIDE.md`](docs/OPERATOR_GUIDE.md) for operating the driver.

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

Only **public** keys are committed. Private signing keys are never stored in this repository; generate your own with `cosign generate-key-pair`, `gpg --gen-key`, or `ulp_pqc_signer.py` (ML-DSA-65) and point `policy.json` at the corresponding public keys.

> **Warning:** This is experimental research code that loads a kernel module and modifies running processes. Use only on disposable test machines.

---

## License

ulp-driver is licensed under the **GNU General Public License v2.0 only** (`GPL-2.0-only`), the same license as the Linux kernel. See [`LICENSE`](LICENSE). The following parts are licensed differently:

| Path | License |
|---|---|
| `ulp-driver/ulp_uapi.h` | `GPL-2.0-only WITH Linux-syscall-note` (userspace programs may include it without becoming GPL, as with kernel uapi headers) |
| `upstream.patch` | `MIT OR Apache-2.0` (matching the Rust compiler, for upstream submission) |
| `rust-livepatch-plugin/` | `Apache-2.0 WITH LLVM-exception` (matching LLVM) |

Full license and exception texts are in [`LICENSES/`](LICENSES/).
