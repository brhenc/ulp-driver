// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
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

        // Configuration via environment variables
        // RUST_LIVEPATCH_PFE: default "16" (16 bytes entry padding)
        const char *pfe_env = std::getenv("RUST_LIVEPATCH_PFE");
        std::string pfe_val = pfe_env ? pfe_env : "16";

        // RUST_LIVEPATCH_NOINLINE: default "1" (prevent inlining of exported symbols)
        const char *noinline_env = std::getenv("RUST_LIVEPATCH_NOINLINE");
        bool force_noinline = (!noinline_env || std::strcmp(noinline_env, "0") != 0);

        // Verbose logging if requested
        bool verbose = (std::getenv("RUST_LIVEPATCH_VERBOSE") != nullptr);

        if (verbose) {
            errs() << "[RustLivepatchPlugin] Processing module: " << M.getName()
                   << " (PFE=" << pfe_val << ", NoInline=" << force_noinline << ")\n";
        }

        size_t patched_fns = 0;
        for (Function &F : M) {
            // Only process functions with actual bodies
            if (F.isDeclaration())
                continue;

            // 1. Inject patchable-function-entry attribute
            F.addFnAttr("patchable-function-entry", pfe_val);

            // 2. Align to 16 bytes for safe instruction patching and cache line safety
            if (!F.getAlign() || *F.getAlign() < Align(16)) {
                F.setAlignment(Align(16));
            }

            // 3. Inlining barrier on exported / non-local functions
            if (force_noinline) {
                if (!F.hasLocalLinkage() && !F.hasAvailableExternallyLinkage()) {
                    F.addFnAttr(Attribute::NoInline);
                    F.removeFnAttr(Attribute::AlwaysInline);
                }
            }

            patched_fns++;
            Modified = true;
        }

        if (verbose) {
            errs() << "[RustLivepatchPlugin] Configured " << patched_fns
                   << " functions for kernel-grade livepatching.\n";
        }

        return Modified ? PreservedAnalyses::none() : PreservedAnalyses::all();
    }
};

} // anonymous namespace

// Register plugin with LLVM New Pass Manager
extern "C" ::llvm::PassPluginLibraryInfo LLVM_ATTRIBUTE_WEAK llvmGetPassPluginInfo() {
    return {
        LLVM_PLUGIN_API_VERSION,
        "RustLivepatchPlugin",
        "0.1.0",
        [](PassBuilder &PB) {
            // 1. Register early in the pipeline so inlining decisions respect attributes
            PB.registerPipelineEarlySimplificationEPCallback(
                [](ModulePassManager &MPM, OptimizationLevel, ThinOrFullLTOPhase) {
                    MPM.addPass(RustLivepatchPass());
                }
            );

            // 2. Also register at pipeline start
            PB.registerPipelineStartEPCallback(
                [](ModulePassManager &MPM, OptimizationLevel) {
                    MPM.addPass(RustLivepatchPass());
                }
            );

            // 3. Register as an explicit named pass (can be run via -C passes=rust-livepatch)
            PB.registerPipelineParsingCallback(
                [](StringRef Name, ModulePassManager &MPM, ArrayRef<PassBuilder::PipelineElement>) {
                    if (Name == "rust-livepatch") {
                        MPM.addPass(RustLivepatchPass());
                        return true;
                    }
                    return false;
                }
            );
        }
    };
}
