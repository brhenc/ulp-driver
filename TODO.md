# TODO

Known shortcomings, roughly in priority order. See also the "Status & limitations" section of the [README](README.md).

## Correctness & safety

- [ ] **Persistent rules don't verify the target binary.** Exec rules (`struct ulp_kernel_rule_req`) match only on `binary_path` + `target_offset`. After a package update replaces the binary, a stale rule writes a trampoline at an offset that now lands inside unrelated code, crashing the service on every start (a crash loop under systemd). Store the binary's build-id (or a content hash) in the rule, check it at exec time, and skip and log stale rules. Touches the uapi struct, the driver's exec matching, and `ulp_persist` save/restore.
- [ ] **Patch application is not atomic.** `ulp_atomic_direct_poke()` writes trampolines with `access_process_vm(FOLL_FORCE)` (copy-on-write plus `memcpy`), with no guarantee of a single 8-byte store. The 16-byte apply path writes bytes 8–15 of live code first. The code comments overstate this ("atomic", "core pipeline sync" for what is an `smp_mb()` IPI).
- [ ] **The quiescence check is racy.** `ulp_verify_thread_quiescence()` reads `task_pt_regs(t)->ip`, which is stale for threads running in userspace on another CPU. Threads are not stopped, so a thread can enter the target between the check and the write. Stop the target's threads for the duration of the write (`ulp_inject` already stops them with ptrace) and retry or back off if one is inside the patched range.

## Portability

- [ ] **The driver builds only on kernels that export `task_work_add`.** Mainline Linux has never exported it. Debian adds the export in `debian/export-symbols-needed-by-android-drivers.patch` (for binder). On Fedora 7.1/7.2 and other mainline-based kernels, the module fails at modpost. It's used only in the exec-rule path (`ulp_exec_task_work_fn`). Earlier upstream attempts to export it were not merged (NVMe RFC 2021, DRM 2021, ublk 2022; see the Jens Axboe and Christoph Hellwig replies in the 2022 thread).
- [ ] **The driver is x86_64 only** (for example, the fork kprobe reads `regs->di`). The other-architecture work exists only as emulated trampoline tests.

## Security

- [ ] **Signatures are not enforced on the injection path.** Neither `ulp_driver.c` nor `ulp_inject.c` verifies payload signatures; `ulp_crypto_verifier.py` is a standalone pre-flight tool.
- [ ] **`ulp_scope=1` cannot apply Yama or LSM ptrace hooks** (`ptrace_may_access()` is not exported). It currently checks matching credentials and dumpability only.
- [ ] **The PQC signer (`ulp_pqc_signer.py`) is a toy, not FIPS 204 ML-DSA:**
  - `expand_a` lacks rejection sampling
  - the secret polynomials don't come from the seed
  - it uses JSON encoding instead of the FIPS format
  - it isn't constant-time

  Replace it with liboqs or OpenSSL 3.5 ML-DSA, or remove it, and drop the "NIST FIPS 204" wording throughout the code and docs.

## Tooling & tests

- [ ] **Example scripts default to `/usr/local/bin/ulp_inject` / `ulp_ctl`.** Stale installed copies silently cause failures (the remote `dlopen` returns NULL and the target dies with SIGILL). Default to the tools in the repo's build directory.
- [ ] **`ulp_inject` leaves the target in a bad state when the remote `dlopen` fails** (the process died with SIGILL after a failed injection). Restore registers and memory on every error path.
- [ ] **Patch validation workflow:** build and test patches against a clone of the exact deployed binary, matched by build-id and library versions, ideally with replayed production traffic.
- [ ] **Patch authoring tooling:** generate patches from a source diff against the deployed build (similar to `kpatch-build`).

## Direction

- [ ] **ptrace-only "break-glass" mode** for unprepared systems where the kernel module can't be loaded (Secure Boot module signing, lockdown, kernels without `task_work_add`). The driver stays the optional layer for managed fleets (persistence, policy, driver reloads).
- [ ] Prefer patch sites reserved by `-fpatchable-function-entry` (see `upstream.patch` for rustc) when available. Fall back to overwriting live instructions for unprepared binaries.

## Docs

- [ ] **Tone down the claims across `docs/`** ("zero-downtime", "100% success", "Enterprise Hardened", "MULTICS-style", "NASA JPL / CERT" comments in the code).
- [ ] **`docs/OPERATOR_GUIDE.md` still lists FRRouting** as a supported target. Decide whether to keep `frr-userspace-livepatch/`.
- [ ] Compare against [SUSE libpulp](https://github.com/SUSE/libpulp) in the docs: no kernel component and NOP-padded patch sites, but shared libraries only, `LD_PRELOAD` required, and no static or Go binaries.
