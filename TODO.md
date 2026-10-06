# TODO

Known shortcomings, roughly in priority order. See also the "Status & limitations" section of the [README](README.md).

## Correctness & safety

- [ ] **Persistent rules don't verify the target binary.** Exec rules (`struct ulp_kernel_rule_req`) match only on `binary_path` + `target_offset`. After a package update replaces the binary, a stale rule writes a trampoline at an offset that now lands inside unrelated code, crashing the service on every start (a crash loop under systemd). Store the binary's build-id (or a content hash) in the rule, check it at exec time, and skip and log stale rules. Touches the uapi struct, the driver's exec matching, and `ulp_persist` save/restore.
- [ ] **Patch application is not atomic.** `ulp_atomic_direct_poke()` writes trampolines with `access_process_vm(FOLL_FORCE)` (copy-on-write plus `memcpy`), with no guarantee of a single 8-byte store. The 16-byte apply path writes bytes 8–15 of live code first. The code comments overstate this ("atomic", "core pipeline sync" for what is an `smp_mb()` IPI).
- [ ] **The quiescence check is racy.** `ulp_verify_thread_quiescence()` reads `task_pt_regs(t)->ip`, which is stale for threads running in userspace on another CPU. Threads are not stopped, so a thread can enter the target between the check and the write. Stop the target's threads for the duration of the write (`ulp_inject` already stops them with ptrace) and retry or back off if one is inside the patched range.

- [ ] **No patchability check: the function length is trusted from the caller.** `ulp_ctl apply ... <func_len>` passes the length through unverified. The driver assumes 16 when it's 0, uses the 5-byte jump under 16, and only refuses under 5. The test suite passes `FUNC_LEN=64` for an ~11-byte function and works only because of `-falign-functions=16` padding. Add a userspace analyzer (in `ulp_ctl` or a separate `ulp_check`) that reports a verdict, "patchable by method X" or "not patchable because Y", and have the driver accept only verified lengths. Checks:
  - **Real function bounds:** ELF `st_size`; `.eh_frame` ranges for stripped binaries; `.gopclntab` for Go (see `go-livepatch-bench/go_sym_resolver.py`). Refuse when bounds are unknown.
  - **Size ≥ trampoline length** (16 absolute, 5 relative). Trailing padding counts only if disassembly confirms it's NOP/`int3`.
  - **No branch targets inside bytes 1..N−1 of the patch window** (for example, loop heads near the function entry), no jump tables in the window, and no code reading the window as data.
  - **The window ends on an instruction boundary.**
  - **A leading `endbr64` is preserved** (CET).
  - **Prefer `-fpatchable-function-entry` NOP sleds** (`__patchable_function_entries`) when present.
  - **Fallbacks:** a GOT-entry swap for PLT-called library functions (an atomic 8-byte pointer write); the 5-byte relative jump for short functions with no inbound branches (payload within ±2 GB); otherwise refuse.

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
- [ ] **Applying a patch requires hand-computed addresses.** `ulp_ctl apply` takes raw hex target and patch addresses. The examples derive them with `nm`, `/proc/<pid>/maps` and inline Python. Add symbol-based arguments, for example `ulp_ctl apply <pid> <binary>:<symbol> <patch.so>:<symbol>`, resolving PIE bases and checking patchability (see the analyzer item above).
- [ ] **`ulp_scope=1` is effectively unusable without `dev_mode`.** Same-user patching still needs an armed window, and only root can arm (via `/dev/ulp` write, which requires `CAP_SYS_ADMIN`), so a root operator has to hold `ulp_ctl arm` open. Decide whether arming should be per-scope, delegable, or documented as root-mediated.
- [ ] **Move the 18 root-level `test_*`/`run_*` scripts** into `tests/` (runnable anywhere) and `scripts/dev-vm/` (tied to the author's VMs: `run_all_tests.sh` and `run_full_reboot_test.sh` ssh to `debian-13`/`fkernel-dev`). Remove personal VM hostnames from the 8 docs that mention them.
- [ ] **Re-run `examples/test_all_examples.sh` from a fresh clone** after the switch to in-repo tool defaults (this needs a host where the module isn't pinned at scope 3).
- [ ] **Patch validation workflow:** build and test patches against a clone of the exact deployed binary, matched by build-id and library versions, ideally with replayed production traffic.
- [ ] **Patch authoring tooling:** generate patches from a source diff against the deployed build (similar to `kpatch-build`).

## Direction

- [ ] **ptrace-only "break-glass" mode** for unprepared systems where the kernel module can't be loaded (Secure Boot module signing, lockdown, kernels without `task_work_add`). The driver stays the optional layer for managed fleets (persistence, policy, driver reloads).
- [ ] Prefer patch sites reserved by `-fpatchable-function-entry` (see `upstream.patch` for rustc) when available. Fall back to overwriting live instructions for unprepared binaries.

## Docs

- [ ] **Tone down the claims across `docs/`** ("zero-downtime", "100% success", "Enterprise Hardened", "MULTICS-style", "NASA JPL / CERT" comments in the code).
- [ ] **`docs/OPERATOR_GUIDE.md` still lists FRRouting** as a supported target. Decide whether to keep `frr-userspace-livepatch/`.
- [ ] Compare against [SUSE libpulp](https://github.com/SUSE/libpulp) in the docs: no kernel component and NOP-padded patch sites, but shared libraries only, `LD_PRELOAD` required, and no static or Go binaries.
