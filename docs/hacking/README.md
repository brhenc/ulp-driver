# ulp-driver: Developer & Kernel Hacking Index

Welcome to the complete internal developer documentation for **ulp-driver** (Userspace Livepatching / ULP). This documentation is organized into 8 comprehensive guides covering architecture, kernel driver internals, low-level injection, multi-language support, cross-architecture porting, database socket mechanics, operator tooling, and upstream LKML submission.

---

## Documentation Navigation Index

| Guide | Description | Key Topics |
| :--- | :--- | :--- |
| [**`00_PROJECT_OVERVIEW_AND_ARCHITECTURE.md`**](/docs/hacking/00_PROJECT_OVERVIEW_AND_ARCHITECTURE.md) | **Master Architecture Blueprint** | System vision, continuous daemon evolution without restarts, end-to-end stack, NASA JPL Power of 10 rules. |
| [**`01_KERNEL_DRIVER_INTERNALS.md`**](/docs/hacking/01_KERNEL_DRIVER_INTERNALS.md) | **Kernel Driver Subsystem (`/dev/ulp`)** | Data structures, Fail-Closed Arming State Machine, atomic 8-byte text poke, dead PID reaping, sysctl ratchet. |
| [**`02_SAFE_INJECTION_AND_TRAMPOLINE_ENGINE.md`**](/docs/hacking/02_SAFE_INJECTION_AND_TRAMPOLINE_ENGINE.md) | **Low-Level Injector (`ulp_inject`)** | Red-zone evasion (`RSP - 512`), neutralizing `ERESTARTSYS` rollback (`orig_rax = -1`), Intel CET IBT, shadow variables. |
| [**`03_MULTI_LANGUAGE_SUPPORT_GUIDE.md`**](/docs/hacking/03_MULTI_LANGUAGE_SUPPORT_GUIDE.md) | **C, C++, Rust & Golang Guide** | Itanium C++ mangling/vtables, Rust memory immutability, Go `ABIInternal` register models & pinned `g` register. |
| [**`04_CROSS_ARCHITECTURE_PORTING_GUIDE.md`**](/docs/hacking/04_CROSS_ARCHITECTURE_PORTING_GUIDE.md) | **6-ISA Cross-Architecture Porting** | `x86_64`, `aarch64`, `riscv64`, `s390x`, `ppc64le`, `loongarch64`, weak memory models, cache flush instructions. |
| [**`05_ADVANCED_DATABASE_PATTERNS_AND_SOCKETS.md`**](/docs/hacking/05_ADVANCED_DATABASE_PATTERNS_AND_SOCKETS.md) | **Database Patterns & Socket Backlogs** | 32-bit $\to$ 64-bit autoinc expansion, dynamic `max_connections`, zero-downtime socket backlog expansion (`ss -tlpn` $80 \to 300$). |
| [**`06_OPERATOR_TOOLING_TUI_AND_AUTOMATION.md`**](/docs/hacking/06_OPERATOR_TOOLING_TUI_AND_AUTOMATION.md) | **Operator Dashboard & Tooling** | Curses TUI (`tools/ulp_tui.py`), Plan 9 VFS telemetry, Cosign/GPG verification, continuous multi-generation suite. |
| [**`07_LKML_SUBMISSION_PLAYBOOK.md`**](/docs/hacking/07_LKML_SUBMISSION_PLAYBOOK.md) | **LKML Upstream Submission Playbook** | `CONFIG_USERSPACE_LIVEPATCH`, reviewer pushback answers (Peter Zijlstra, Josh Poimboeuf), `checkpatch.pl`, patch submission. |
| [**`08_DEVELOPMENT_ENVIRONMENT_AND_TESTING.md`**](/docs/hacking/08_DEVELOPMENT_ENVIRONMENT_AND_TESTING.md) | **Development & Test Automation** | Debian 13 VM (`192.168.122.171`), building `ulp_driver.ko`, running all automated benchmarks, writing new livepatches. |
| [**`09_CANARY_LIVEPATCHING_AND_CRASH_RESILIENCE.md`**](/docs/hacking/09_CANARY_LIVEPATCHING_AND_CRASH_RESILIENCE.md) | **Canary Routing & MULTICS Fault Recovery** | Progressive 1% canary traffic sampling, Tramp-Backup passthrough, zero-crash SEGV fault trapping, and kernel auto-rollback. |
| [**`10_POST_QUANTUM_CRYPTO_AND_SIGNING.md`**](/docs/hacking/10_POST_QUANTUM_CRYPTO_AND_SIGNING.md) | **Post-Quantum Crypto (PQC) & Hybrid Attestation** | NIST FIPS 204 ML-DSA-65 (CRYSTALS-Dilithium), Linux in-kernel PQC feasibility (SHAKE-256), Cosign PQC roadmap, Hybrid signing envelopes. |

---

## Quick Reference: Running the Test Suites

```bash
# 1. Multi-Daemon Continuous Evolution Suite (pgrust, MariaDB, Postgres, HAProxy)
python3 tests/test_multi_version_continuous_suite.py

# 2. MariaDB Zero-Downtime Socket Backlog Expansion (ss -tlpn Send-Q 80 -> 300)
python3 mariadb-livepatch-bench/test_socket_backlog_live_expansion.py

# 3. Golang Multi-Version Continuous Livepatch Suite (server_go)
python3 go-livepatch-bench/test_go_continuous_livepatch.py

# 4. Cross-Architecture 6-ISA QEMU Emulation Benchmark
python3 cross-arch-bench/run_cross_arch_emulation_suite.py

# 5. Canary Traffic Splitting & Crash Resilience Suite
python3 test_canary_resilience_suite.py

# 6. Post-Quantum & Hybrid Signature Verification Suite
python3 tests/test_pqc_verification_suite.py

# 7. Operator Terminal UI Dashboard
python3 tools/ulp_tui.py
```
