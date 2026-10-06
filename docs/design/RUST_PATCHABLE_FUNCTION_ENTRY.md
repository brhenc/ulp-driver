# docs/design/RUST_PATCHABLE_FUNCTION_ENTRY.md
## Architectural Specification: Natively Livepatchable Rust (`rustc` Livepatch Profile)

**Author:** ulp-driver Architecture Team  
**Status:** Proposal / Draft RFC  
**Target:** `rust-lang/rust` (Compiler Backend, MIR Passes, Codegen LLVM)  
**Date:** September 2026  

---

## 1. Executive Summary & Problem Statement

Userspace Livepatching (ULP) allows security patches, hotfixes, and structural updates to be applied to running mission-critical software (databases, proxies, routing daemons) without restarting processes or dropping client connections. While C programs can be made livepatchable using well-established compiler options (such as GCC's `-fpatchable-function-entry=N,M` and `-fno-inline-functions-called-once`), **Rust currently lacks first-class compiler primitives for runtime livepatching**.

Our livepatching experiments with `pgrust` (PostgreSQL rewrite in Rust) proved that while x86_64 Rust machine code is physically patchable via kernel trampoline injection (`/dev/ulp`), `rustc`'s aggressive optimization passes create severe impediments:

1. **Sub-16-Byte Leaf Overwrites**: Tiny leaf functions (3–8 bytes) lack sufficient prologue bytes for a 16-byte CET-compliant absolute trampoline (`endbr64 + movabs $addr, %rax; jmpq *%rax`), causing trampolines to overwrite adjacent functions.
2. **Generic Monomorphization & Inlining Erasure**: Monomorphized generic functions (`fn handle<T>(...)`) are aggressively dissolved into callers by LLVM ThinLTO, destroying their existence as discrete, patchable ELF symbols.
3. **Struct Layout Instability**: Default `repr(Rust)` struct layouts vary between compiler versions, optimization levels, and hash seeds, risking field offset corruption during live updates.
4. **Suspended Async State Machines**: Coroutine state machines for `async fn` lack layout versioning, preventing livepatching of asynchronous server loops where tasks remain suspended at `.await` yield points.

This document specifies the concrete compiler enhancements required in `rustc` to provide a first-class **Livepatch Profile** (`-C livepatch-profile`).

---

## 2. Compiler Modifications Architecture

```
                    ┌─────────────────────────────────────────────────────────┐
                    │                      rustc Driver                       │
                    └────────────────────────────┬────────────────────────────┘
                                                 │
                                                 ▼
             ┌──────────────────────────────────────────────────────────────────────┐
             │ Session & CLI: -C patchable-function-entry, -C livepatch-profile     │
             │ File: compiler/rustc_session/src/config.rs                           │
             └───────────────────────────────────┬──────────────────────────────────┘
                                                 │
                   ┌─────────────────────────────┴─────────────────────────────┐
                   ▼                                                           ▼
┌──────────────────────────────────────┐                   ┌──────────────────────────────────────┐
│       HIR / MIR Optimization         │                   │          LLVM Code Generation        │
├──────────────────────────────────────┤                   ├──────────────────────────────────────┤
│ 1. Inlining Barrier for Boundaries   │                   │ 1. LLVM Function Entry Padding       │
│    (compiler/rustc_mir_transform/)   │                   │    "patchable-function-entry"="16,0" │
│ 2. Coroutine State Versioning Header │                   │    (compiler/rustc_codegen_llvm/)    │
│    (coroutine.rs async state tags)   │                   │ 2. Stable AMD64 Calling Convention   │
│ 3. Deterministic Layout Sorter       │                   │ 3. Monomorphized Stub Exporting      │
│    (compiler/rustc_middle/ty/layout) │                   │    (compiler/rustc_codegen_ssa/)     │
└──────────────────────────────────────┘                   └──────────────────────────────────────┘
```

---

## 3. Detailed Technical Specifications

### Phase 1: Function Entry Padding (`-C patchable-function-entry=N,M`)

#### Objective
Guarantee that every compiled function prologue contains at least 16 contiguous bytes of dedicated landing space (NOP sled or alignment pad) to allow atomic 16-byte absolute trampoline injection without corrupting preceding or succeeding code.

#### Mechanism in LLVM
LLVM already supports function entry padding via function attributes:
```llvm
define void @my_function() #0 {
    ...
}
attributes #0 = { "patchable-function-entry"="16,0" }
```
When LLVM compiles this attribute for x86_64, it emits:
```assembly
my_function:
    .byte 0xeb, 0x0e             ; Short jump over 14 bytes NOP padding (or 16 NOPs)
    nop
    nop
    ...
    ; Real function body starts here
```

#### Modifications in `rustc`
1. **`compiler/rustc_session/src/config.rs`**:
   Add codegen option:
   ```rust
   pub struct CodegenOptions {
       ...
       pub patchable_function_entry: Option<String>, // "N,M"
   }
   ```
2. **`compiler/rustc_codegen_llvm/src/attributes.rs`**:
   Attach the attribute during LLVM function declaration:
   ```rust
   if let Some(ref pfe) = cx.tcx.sess.opts.cg.patchable_function_entry {
       let val = llvm::to_llvm_str(pfe);
       llvm::AddCallSiteAttribute(llfn, llvm::Attribute::get(cx.llcx, "patchable-function-entry", val));
   }
   ```

---

### Phase 2: Inlining Control & Monomorphization Stubs (`-C livepatch-boundaries`)

#### Objective
Ensure that functions marked for livepatching—or all public crate boundary functions—retain distinct, addressable ELF machine code entry points and are not completely dissolved into call sites.

#### Mechanism
1. **MIR Inliner Filter (`compiler/rustc_mir_transform/src/inline.rs`)**:
   When `-C livepatch-boundaries` is active, skip inlining for:
   - Any function annotated with `#[livepatchable]` or `#[no_mangle]`.
   - Public non-generic crate functions.
2. **Out-of-Line Generic Stubs (`compiler/rustc_codegen_ssa/src/back/symbol_export.rs`)**:
   For each monomorphized generic instance `foo::<MyType>()`, generate an explicit non-inline ELF symbol in `.text` and export it in `.symtab` so that patch tools can resolve its virtual address.

---

### Phase 3: Calling Convention & Register Allocation Stability

#### Objective
Prevent LLVM from performing Scalar Replacement of Aggregates (SRA) on function argument boundaries or inventing arbitrary, unstable register allocations between compilation runs of the host and patch libraries.

#### Mechanism
1. **ABI Normalization**:
   Introduce attribute `#[livepatchable]` which implicitly enforces `extern "C"` calling convention (System V AMD64) and prohibits splitting aggregates across disparate registers.
2. **Pointers vs Direct Aggregates**:
   Ensure large structs are passed by pointer (`*const T` / `*mut T`) rather than register-packed values when crossing livepatchable boundaries.

---

### Phase 4: Deterministic `repr(Rust)` Struct Layouts (`-C repr-deterministic`)

#### Objective
Prevent compiler hash seeds and optimization flags from changing struct field offsets across distinct builds of the same source code.

#### Mechanism in `compiler/rustc_middle/src/ty/layout.rs`
1. Replace hash-based field ordering with deterministic lexicographical ordering (by field name, then type size/alignment).
2. Emit an ELF metadata section `.rustc_type_layouts` recording:
   - Type Name / Symbol
   - Size and Alignment
   - Field offsets and types

---

### Phase 5: Resumable Async/Coroutine State-Machine Migration

#### Objective
Enable livepatching of server event loops (Tokio, async-std) where long-running connections are actively suspended at `.await` yield points.

#### Mechanism in `compiler/rustc_mir_transform/src/coroutine.rs`
1. **Header Tag**: Every generated coroutine struct begins with a standardized 8-byte header:
   ```rust
   #[repr(C)]
   struct CoroutineHeader {
       magic: u32,        // 0x52555354 ('RUST')
       version: u16,      // State machine layout version
       current_state: u16,// Current .await yield point index
   }
   ```
2. **Migration Dispatch in `Future::poll()`**:
   When `poll()` is invoked, it verifies `header.version`. If a newer livepatch altered the state layout, it dispatches to a user-provided `migrate(old_state, old_version)` hook prior to execution.

---

## 4. Proposed `rustc` Command-Line Interface

```bash
# Compile a binary ready for kernel-grade livepatching:
rustc -C livepatch-profile=full \
      -C patchable-function-entry=16,0 \
      -C repr-deterministic=yes \
      -C link-arg=-Wl,--export-dynamic \
      main.rs -o my_daemon
```

### Profile Levels:
- **`minimal`**: Enables `-C patchable-function-entry=16,0` (solves leaf-function overwrites; zero runtime overhead).
- **`standard`**: `minimal` + deterministic struct layouts + inlining barriers on public functions.
- **`full`**: `standard` + monomorphization stubs + async coroutine headers.

---

## 5. Implementation Roadmap

| Milestone | Target Component | Description | Complexity |
| :--- | :--- | :--- | :--- |
| **M1** | `rustc_session` + `rustc_codegen_llvm` | Add `-C patchable-function-entry=N,M` exposing LLVM attribute. | Low (1–2 days) |
| **M2** | `rustc_middle/ty/layout.rs` | Add `-C repr-deterministic` for stable struct layouts. | Medium (3–5 days) |
| **M3** | `rustc_mir_transform/inline.rs` | Implement `#[livepatchable]` attribute to prevent inline erasure. | Medium (5–7 days) |
| **M4** | `rustc_codegen_ssa` | Emit `.rustc_patch_info` ELF metadata section for symbol mapping. | Medium (5–7 days) |
| **M5** | `rustc_mir_transform/coroutine.rs` | Implement async state machine version headers and migration dispatch. | High (2–3 weeks) |

---

## 6. Verification with ulp-driver

Once Milestone 1 is implemented, ulp-driver's `test_rust_livepatch_pgrust.py` harness will be used to verify:
1. Zero overwrites on ultra-short (<16 byte) Rust functions.
2. 100% atomic kernel livepatching under 64-thread concurrent query load.
3. Seamless rollback and zero memory corruption.
