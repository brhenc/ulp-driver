# Rust Livepatch LLVM Plugin (`libRustLivepatchPlugin.so`)

A drop-in LLVM New Pass Manager plugin for **`rustc`** that makes Rust applications natively and safely livepatchable with kernel-grade livepatching drivers like ulp-driver's `/dev/ulp`.

---

## 1. The Problem Solved

Standard `rustc` binaries suffer from the **Sub-16-Byte Leaf Overwrite Problem**:
```assembly
; Vanilla Rust output for `pub fn is_ready(&self) -> bool { self.ready }`
0000000000005930 <is_ready>:
    5930: 8d 47 01         lea  0x1(%rdi),%eax
    5933: c3               ret                         ; Total length: 4 BYTES!
0000000000005940 <next_function>:
    5940: 50               push %rax
```
When a kernel driver injects an atomic 16-byte CET-compliant absolute trampoline (`endbr64 + movabs $target, %rax; jmpq *%rax`), the 16 bytes overwrite `is_ready` AND the first 12 bytes of `next_function`, causing crashes in adjacent code.

---

## 2. How the Plugin Works

The plugin registers callbacks with LLVM's New Pass Manager (`PassBuilder`), intercepting all LLVM IR modules emitted by `rustc`:

1. **`patchable-function-entry = 16`**: Injects dedicated 16-byte multi-byte NOP landing sleds at the prologue of every function with a body.
2. **16-Byte Alignment (`Align(16)`)**: Enforces 16-byte function alignment, preventing cross-cache-line atomicity hazards when patching.
3. **Inlining Barrier (`NoInline`)**: Prevents LLVM from dissolving exported / public functions into callers, guaranteeing they remain discrete, addressable ELF symbols.

### Disassembly with Plugin Active:
```assembly
00000000000059a0 <tiny_leaf>:
    59a0: 66 66 66 66 66 2e 66 data16 data16 data16 data16 data16 cs nopw 0x200(%rax,%rax,1)
    59a7: 0f 1f 84 00 00 02 00 
    59ae: 00 
    59af: 90                   nop                    ; <-- 16 BYTES OF DEDICATED PADDING!
    59b0: 8d 47 01             lea    0x1(%rdi),%eax  ; <-- Real function body begins here
    59b3: c3                   ret
```
The 16-byte livepatch trampoline overwrites **only** the `59a0 - 59af` padding sled! The original function body and subsequent functions remain completely untouched.

---

## 3. How to Use with Any Rust Project

### Step 1: Build the Plugin
```bash
cd rust-livepatch-plugin
make
# Generates libRustLivepatchPlugin.so
```

### Step 2: Enable in Cargo (`.cargo/config.toml`)
Add the following to your project's `.cargo/config.toml`:

```toml
[target.'cfg(all())']
rustflags = [
    "-Z", "llvm-plugins=/path/to/libRustLivepatchPlugin.so",
    "-C", "link-arg=-Wl,--export-dynamic"
]
```

Or pass via environment variable:
```bash
RUSTC_BOOTSTRAP=1 RUSTFLAGS="-Z llvm-plugins=/path/to/libRustLivepatchPlugin.so" cargo build
```

---

## 4. Configuration Options (Environment Variables)

| Variable | Default | Description |
| :--- | :--- | :--- |
| `RUST_LIVEPATCH_PFE` | `16` | Number of NOP bytes allocated at function entry (16 matches CET absolute trampoline size). |
| `RUST_LIVEPATCH_NOINLINE` | `1` | `1` to prevent inlining of non-local functions; `0` to allow default inlining. |
| `RUST_LIVEPATCH_VERBOSE` | *(unset)* | Set to `1` to display module and function counts during compilation. |

---

## 5. Compatibility

- **Rust Compiler**: Compatible with standard `rustc` (1.85+) linking against LLVM.
- **Architectures**: `x86_64` (full CET `endbr64` + 16-byte trampoline support), `aarch64`.
- **Operating Systems**: Linux (Debian 13, Fedora 44, RHEL, Ubuntu).
