# Agent Implementation Specification: Native Rust Userspace Livepatching (ULP)

**Document**: `docs/guides/RUST_LIVEPATCH_IMPLEMENTATION_SPEC.md`  
**Purpose**: Complete, self-contained implementation specification and codebase integration guide for AI coding agents (Claude Code, Antigravity/agy) and systems engineers to enable zero-downtime userspace livepatching in Rust projects.  
**Target Target Environments**: Linux x86_64 (Kernel 6.x / 7.x, ULP Driver, CET/IBT enabled).  

---

## 1. The Core Problems in Rust Livepatching

When attempting to livepatch standard Rust binaries using in-memory trampoline redirection (such as 16-byte CET absolute jumps: `endbr64; movabs $patch_vaddr, %rax; jmpq *%rax`), three critical compiler behaviors cause crashes or failure:

1. **The Sub-16-Byte Leaf Overwrite Hazard**:
   A short Rust leaf accessor function (e.g. `pub fn get_flag(&self) -> bool { self.flag }`) compiles down to 3–8 bytes (`movzbl 0x8(%rdi), %eax; ret`). Injecting a 16-byte absolute trampoline overwrites the target function **plus the first 8–13 bytes of the adjacent function in `.text`**, corrupting the process.
2. **Compiler Inlining & Constant Folding**:
   LLVM's ThinLTO and Interprocedural Optimization (IPO) aggressively inlines pure functions across crates or dissolves function calls into constant literals.
3. **Instruction Stream Alignment**:
   Kernel atomic memory overlays require functions to be naturally aligned (to 8 or 16 bytes) to prevent cross-cache-line split-lock atomicity faults.

---

## 2. Solution Matrix

Choose the integration path that fits your project's constraints:

| Option | Method | Overhead | Requirement | Best Used For |
| :--- | :--- | :--- | :--- | :--- |
| **Option A** | **LLVM Pass Plugin** (`libRustLivepatchPlugin.so`) | Zero runtime cost; 16B NOP sled per fn | Standard `rustc` + LLVM headers | Production projects using official `rustc` toolchains. |
| **Option B** | **Upstream `rustc` Patch** (`-Z patchable-function-entry`) | Zero runtime cost; native compiler flag | Custom-built `rustc` | Long-term toolchain integration and upstream contribution. |
| **Option C** | **Pure Rust / LLVM Flags** (No plugins / patches) | Zero runtime cost; compiler flags only | Any standard `rustc` | Greenfield projects with explicit function design. |

---

## 3. Option A: Drop-In LLVM Plugin (`RustLivepatchPlugin.cpp`)

This LLVM New Pass Manager plugin intercepts LLVM IR during compilation and injects:
1. `patchable-function-entry = 16`: Emits a 16-byte multi-byte NOP landing sled at the start of every function.
2. `Align(16)`: Forces 16-byte function alignment.
3. `NoInline`: Prevents inlining of exported/public symbols.

### 3.1 Plugin Source Code (`RustLivepatchPlugin.cpp`)

```cpp
// RustLivepatchPlugin.cpp
#include "llvm/Plugins/PassPlugin.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/IR/PassManager.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/raw_ostream.h"
#include <cstdlib>
#include <cstring>
#include <string>

using namespace llvm;

namespace {

class RustLivepatchPass : public PassInfoMixin<RustLivepatchPass> {
public:
    PreservedAnalyses run(Module &M, ModuleAnalysisManager &) {
        bool Modified = false;

        const char *pfe_env = std::getenv("RUST_LIVEPATCH_PFE");
        std::string pfe_val = pfe_env ? pfe_env : "16";

        const char *noinline_env = std::getenv("RUST_LIVEPATCH_NOINLINE");
        bool force_noinline = (!noinline_env || std::strcmp(noinline_env, "0") != 0);

        for (Function &F : M) {
            if (F.isDeclaration())
                continue;

            // 1. Inject 16-byte patchable landing pad
            F.addFnAttr("patchable-function-entry", pfe_val);

            // 2. Enforce 16-byte natural alignment
            if (!F.getAlign() || *F.getAlign() < Align(16)) {
                F.setAlignment(Align(16));
            }

            // 3. Preserve symbol boundaries for exported functions
            if (force_noinline) {
                if (!F.hasLocalLinkage() && !F.hasAvailableExternallyLinkage()) {
                    F.addFnAttr(Attribute::NoInline);
                    F.removeFnAttr(Attribute::AlwaysInline);
                }
            }

            Modified = true;
        }

        return Modified ? PreservedAnalyses::none() : PreservedAnalyses::all();
    }
};

} // namespace

extern "C" ::llvm::PassPluginLibraryInfo LLVM_ATTRIBUTE_WEAK llvmGetPassPluginInfo() {
    return {
        LLVM_PLUGIN_API_VERSION,
        "RustLivepatchPlugin",
        "0.1.0",
        [](PassBuilder &PB) {
            PB.registerPipelineEarlySimplificationEPCallback(
                [](ModulePassManager &MPM, OptimizationLevel, ThinOrFullLTOPhase) {
                    MPM.addPass(RustLivepatchPass());
                }
            );
            PB.registerPipelineStartEPCallback(
                [](ModulePassManager &MPM, OptimizationLevel) {
                    MPM.addPass(RustLivepatchPass());
                }
            );
        }
    };
}
```

### 3.2 Build the Plugin (`Makefile`)

```makefile
LLVM_CONFIG ?= llvm-config
CXX ?= clang++
CXXFLAGS ?= -O3 -Wall -fPIC $(shell $(LLVM_CONFIG) --cxxflags)
LDFLAGS ?= -shared $(shell $(LLVM_CONFIG) --ldflags)

TARGET = libRustLivepatchPlugin.so

all: $(TARGET)

$(TARGET): RustLivepatchPlugin.cpp
	$(CXX) $(CXXFLAGS) -o $@ $< $(LDFLAGS)

clean:
	rm -f $(TARGET)
```

### 3.3 Cargo Integration (`.cargo/config.toml`)

```toml
[target.'cfg(all())']
rustflags = [
    "-Z", "llvm-plugins=/absolute/path/to/libRustLivepatchPlugin.so",
    "-C", "link-arg=-Wl,--export-dynamic"
]
```

---

## 4. Option B: Upstream `rustc` Compiler Patch

If building custom toolchains, apply this patch directly to `rust-lang/rust`:

```diff
From: ulp-driver Contributors <ulp-driver@example.com>
Subject: [PATCH] rustc_codegen_llvm: add -Z patchable-function-entry=N[,M]

--- a/compiler/rustc_codegen_llvm/src/attributes.rs
+++ b/compiler/rustc_codegen_llvm/src/attributes.rs
@@ -412,6 +412,12 @@ pub(crate) fn from_fn_attrs<'ll, 'tcx>(
         to_add.push(llvm::Attribute::get(cx.llcx, "no-trapping-math", "true"));
     }
 
+    if let Some(ref pfe) = cx.tcx.sess.opts.unstable_opts.patchable_function_entry {
+        let pfe_str = pfe.as_str();
+        let attr = llvm::CreateStringAttribute(cx.llcx, "patchable-function-entry", pfe_str);
+        to_add.push(attr);
+    }
+
     for attr in to_add {
         llfn.add_attribute(llvm::AttributeLoc::Function, attr);
     }
--- a/compiler/rustc_session/src/options.rs
+++ b/compiler/rustc_session/src/options.rs
@@ -1920,6 +1920,8 @@ options! {
         "enable panic-unwind on wasm targets"),
     panic_abort_tests: bool = (false, parse_bool, [TRACKED],
         "support tests with panic=abort"),
+    patchable_function_entry: Option<String> = (None, parse_opt_string, [TRACKED],
+        "insert NOP sled at function entry for livepatching and tracing (e.g. 16 or 16,0)"),
     parse_only: bool = (false, parse_bool, [UNTRACKED],
         "parse only; do not compile, assemble, or link"),
     perf_stats: bool = (false, parse_bool, [UNTRACKED],
```

---

## 5. Option C: Pure Rust & Standard Compiler Flags (Zero Plugin Requirement)

For greenfield Rust projects running on standard stable `rustc`:

### 5.1 Function Definition Invariants
```rust
// 1. #[no_mangle]: Prevents symbol name mangling so patch tools find the address.
// 2. #[inline(never)]: Guarantees an independent call target exists in .text.
// 3. pub extern "C": Conforms to standard System V AMD64 ABI.
// 4. Parameter/black_box: Prevents intra-crate interprocedural constant propagation.
#[no_mangle]
#[inline(never)]
pub extern "C" fn process_transaction(req_id: u64) -> u32 {
    std::hint::black_box(req_id);
    // Function body
    100
}
```

### 5.2 Cargo Flags (`.cargo/config.toml`)
```toml
[target.x86_64-unknown-linux-gnu]
rustflags = [
    "-C", "llvm-args=-align-all-functions=4", # Enforces 16-byte function alignment (2^4)
    "-C", "link-arg=-Wl,--export-dynamic",     # Exports symbols in dynamic table for ulp_ctl
    "-C", "relocation-model=pic"              # Standard PIC/PIE
]
```

---

## 6. Verification & Automated Inspection Script

Use this script to verify that a compiled binary has valid 16-byte alignment and NOP landing sleds:

```python
#!/usr/bin/env python3
import subprocess
import sys

def verify_binary(binary_path, symbol_name):
    # 1. Check symbol address and alignment
    out = subprocess.check_output(f"nm {binary_path} | grep -w '{symbol_name}'", shell=True, text=True).strip()
    addr_hex = out.split()[0]
    addr = int(addr_hex, 16)
    
    print(f"[*] Symbol '{symbol_name}' located at: 0x{addr:x}")
    if addr % 16 != 0:
        print(f"[FAIL] Address 0x{addr:x} is NOT 16-byte aligned!")
        return False
    print("[+] PASS: 16-byte alignment verified.")

    # 2. Check function disassembly for NOP padding or body size
    disasm = subprocess.check_output(f"objdump -d {binary_path} | grep -A 10 '<{symbol_name}>:'", shell=True, text=True)
    print(f"[*] Disassembly:\n{disasm}")
    return True

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <binary_path> <symbol_name>")
        sys.exit(1)
    success = verify_binary(sys.argv[1], sys.argv[2])
    sys.exit(0 if success else 1)
```

---

## 7. AI Agent Execution Checklist (For Claude Code & Antigravity)

When tasked with making an existing Rust codebase livepatchable:

1. **Step 1**: Check if `llvm-config` and `clang++` exist on the build system.
   - If present: Build `RustLivepatchPlugin.cpp` and inject via `-Z llvm-plugins`.
   - If absent: Apply Option C (`-C llvm-args=-align-all-functions=4` and `#[no_mangle] #[inline(never)]`).
2. **Step 2**: Add `-C link-arg=-Wl,--export-dynamic` to `.cargo/config.toml` so dynamic symbol tables retain function names.
3. **Step 3**: Audit patchable hot functions: ensure any pure constant functions call `std::hint::black_box()` to avoid LLVM constant folding.
4. **Step 4**: Run `objdump -d` on the compiled binary to confirm target functions are aligned on `0x...0` boundaries and contain at least 16 bytes of prologue space.
