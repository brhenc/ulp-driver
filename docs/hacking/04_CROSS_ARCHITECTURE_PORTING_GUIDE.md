# Cross-Architecture Porting & ISA Verification Guide

**Module:** CPU Architectures & Hardware Backends  
**Supported ISAs:** `x86_64`, `aarch64` (ARM64), `riscv64`, `s390x` (IBM Z), `ppc64le` (PowerPC), `loongarch64`  
**Path:** `docs/hacking/04_CROSS_ARCHITECTURE_PORTING_GUIDE.md`  

---

## 1. Overview & Architecture Portability

To support upstream Linux kernel inclusion, the ULP subsystem is designed to be strictly decoupled from any single CPU architecture. The UAPI ([`ulp_uapi.h`](/ulp-driver/ulp_uapi.h)) operates on generic virtual addresses, while the architecture backend generates the native unconditional branch trampoline for each ISA.

---

## 2. Complete Architecture Specification Matrix

| Feature | `x86_64` | `aarch64` (ARM64) | `riscv64` (RISC-V) | `s390x` (IBM Z) | `ppc64le` (PowerPC) | `loongarch64` |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Instruction Size** | Variable (1–15B) | Fixed 32-bit (4B) | Fixed 32-bit / 16-bit | Variable 16/32/48-bit | Fixed 32-bit (4B) | Fixed 32-bit (4B) |
| **Branch Trampoline** | `movabs $addr, %r11; jmpq *%r11` (13B) | `ldr x16, #8; br x16; .quad <addr>` (16B) | `auipc t0, 0; ld t0, 12(t0); jr t0` (16B) | `lgrl %r1, .+8; br %r1; .quad <addr>` (16B) | `b <offset>` / `mtctr r12; bctr` (16B) | `pcaddu18i $t0, 0; ld.d $t0, 16; jirl $r0, $t0, 0` (16B) |
| **Scratch Register** | `%r11` | `X16` (IP0) / `X17` (IP1) | `t0` (x5) / `t1` (x6) | `%r1` | `r11` / `r12` (TOC/Env) | `$t0` ($r12) / `$t1` ($r13) |
| **Memory Model** | **TSO** (Total Store Order) | **Weakly Ordered** | **Weakly Ordered (RVWMO)**| **Strict Serialization** | **Weakly Ordered** | **Weakly Ordered** |
| **Cache Invalidation**| `sync_core()` / IPI | `DC CVAU` + `IC IVAU` + `ISB` | `FENCE.I` across all harts | `BCR 15, 0` | `dcbst` + `icbi` + `isync` | `ibar 0` / `cacop` |
| **Landing Pad** | CET IBT (`endbr64`) | ARM BTI (`bti c`) | RISC-V Zicfilp (`lpad`) | None required | None required | None required |

---

## 3. Trampoline Bytecode Generators by Architecture

### 3.1 x86_64 (16-Byte CET Absolute Trampoline)
```c
/* f3 0f 1e fa 49 bb <8B addr> 41 ff e3 */
uint8_t code[16] = {
    0xf3, 0x0f, 0x1e, 0xfa,                         /* endbr64 */
    0x49, 0xbb,                                     /* movabs $target, %r11 */
    0, 0, 0, 0, 0, 0, 0, 0,                         /* 8-byte target address (LE) */
    0x41, 0xff, 0xe3                                /* jmpq *%r11 */
};
*(uint64_t *)(&code[6]) = target_addr;
```

### 3.2 aarch64 (16-Byte ARM64 Literal Branch)
```c
/* 50 00 00 58 00 02 1f d6 <8B addr> */
uint32_t code[4] = {
    0x58000050,                                     /* ldr x16, #8 */
    0xd61f0200,                                     /* br x16 */
    (uint32_t)(target_addr & 0xFFFFFFFF),           /* Low 32 bits */
    (uint32_t)(target_addr >> 32)                   /* High 32 bits */
};
```

### 3.3 riscv64 (16-Byte RISC-V Absolute PC-Relative Jump)
```c
/* 97 02 00 00 83 b2 0c 00 82 82 01 00 <8B addr> */
uint32_t code[4] = {
    0x00000297,                                     /* auipc t0, 0 */
    0x00c2b283,                                     /* ld t0, 12(t0) */
    0x00018282,                                     /* jr t0 (c.jr) + nop (c.nop) */
    0x00000000                                      /* Alignment padding */
};
/* Literal pool stored at offset 16 */
```

### 3.4 s390x (16-Byte IBM Z Grand Relative Long Branch)
```c
/* c4 18 00 00 00 04 07 f1 <8B addr BE> */
uint8_t code[16] = {
    0xc4, 0x18, 0x00, 0x00, 0x00, 0x04,             /* lgrl %r1, .+8 */
    0x07, 0xf1,                                     /* br %r1 */
    0, 0, 0, 0, 0, 0, 0, 0                          /* 8-byte Big-Endian Target */
};
*(uint64_t *)(&code[8]) = __builtin_bswap64(target_addr);
```

### 3.5 ppc64le (PowerPC 64 ELFv2 Branch)
```c
/* Direct branch to patch_addr */
uint32_t branch_insn = 0x48000000 | ((offset & 0x03FFFFFC));
```

### 3.6 loongarch64 (16-Byte LoongArch Absolute Branch)
```c
/* 0c 00 00 1e 8c 41 c0 28 80 01 00 4c 00 00 40 03 <8B addr> */
uint32_t code[4] = {
    0x1e00000c,                                     /* pcaddu18i $t0, 0 */
    0x28c0418c,                                     /* ld.d $t0, $t0, 16 */
    0x4c000180,                                     /* jirl $r0, $t0, 0 (jr $t0) */
    0x03400000                                      /* nop */
};
```

---

## 4. Testing Multi-Architecture Livepatches via QEMU

We validate all 6 architectures locally without physical hardware using **QEMU Static User Emulation** and **LLD Linker**:

```bash
# Run the automated 6-architecture test runner
python3 cross-arch-bench/run_cross_arch_emulation_suite.py
```

### Compilation Command Pattern:
```bash
clang -fuse-ld=lld -nostdlib -static --target=<target-triple> -o bin_<arch> test_<arch>.s
qemu-<arch>-static ./bin_<arch>
```
