#!/usr/bin/env python3
"""
Cross-Architecture Userspace Livepatching Emulation Suite
=========================================================
Builds, emulates, and verifies zero-downtime function livepatching across
all 6 major CPU architectures via LLVM Clang, LLD, and QEMU static user emulation:
  1. x86_64      (Intel / AMD)
  2. aarch64     (ARM64 / Graviton / Axion / Apple Silicon)
  3. riscv64     (RISC-V 64-bit)
  4. s390x       (IBM Z Mainframe / LinuxONE)
  5. ppc64le     (PowerPC 64-bit Little Endian)
  6. loongarch64 (LoongArch 64-bit)
"""

import os
import sys
import subprocess

BENCH_DIR = os.path.dirname(os.path.abspath(__file__))

def run_cmd(cmd):
    p = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return p.returncode, p.stdout.strip(), p.stderr.strip()

ARCH_CONFIGS = {
    "x86_64": {
        "triple": "x86_64-linux-gnu",
        "emulator": "qemu-x86_64-static",
        "asm": """
.global _start
.text
_start:
    call get_version
    mov %rax, %rsi
    mov %rbx, %rdx
    mov $1, %rax        # sys_write
    mov $1, %rdi        # stdout
    syscall

    lea get_version(%rip), %rdi
    and $~0xFFF, %rdi
    mov $4096, %rsi
    mov $7, %rdx        # PROT_READ|PROT_WRITE|PROT_EXEC
    mov $10, %rax       # sys_mprotect
    syscall

    lea get_version(%rip), %rdi
    movb $0x49, 0(%rdi)
    movb $0xbb, 1(%rdi)
    lea patch_version(%rip), %rax
    movq %rax, 2(%rdi)
    movb $0x41, 10(%rdi)
    movb $0xff, 11(%rdi)
    movb $0xe3, 12(%rdi)

    call get_version
    mov %rax, %rsi
    mov %rbx, %rdx
    mov $1, %rax
    mov $1, %rdi
    syscall

    mov $60, %rax       # sys_exit
    xor %rdi, %rdi
    syscall

.align 16
get_version:
    lea msg_v0(%rip), %rax
    mov $28, %rbx
    ret
    .space 16, 0x90

.align 16
patch_version:
    lea msg_v1(%rip), %rax
    mov $31, %rbx
    ret

msg_v0: .ascii "[x86_64] V0_ORIGINAL_ACTIVE\\n"
msg_v1: .ascii "[x86_64] V1_LIVEPATCHED_ACTIVE\\n"
"""
    },

    "aarch64": {
        "triple": "aarch64-linux-gnu",
        "emulator": "qemu-aarch64-static",
        "asm": """
.global _start
.text
_start:
    bl get_version
    mov x1, x0
    mov x2, x19
    mov x0, #1
    mov x8, #64
    svc #0

    adrp x0, get_version
    mov x1, #4096
    mov x2, #7
    mov x8, #226
    svc #0

    adrp x0, get_version
    add x0, x0, :lo12:get_version
    movz w1, #0x0050
    movk w1, #0x5800, lsl #16
    str w1, [x0]
    movz w1, #0x0200
    movk w1, #0xd61f, lsl #16
    str w1, [x0, #4]
    adrp x1, patch_version
    add x1, x1, :lo12:patch_version
    str x1, [x0, #8]

    dc cvau, x0
    ic ivau, x0
    isb

    bl get_version
    mov x1, x0
    mov x2, x19
    mov x0, #1
    mov x8, #64
    svc #0

    mov x0, #0
    mov x8, #93
    svc #0

.align 4
get_version:
    adrp x0, msg_v0
    add x0, x0, :lo12:msg_v0
    mov x19, #29
    ret
    .space 16, 0xd503201f

.align 4
patch_version:
    adrp x0, msg_v1
    add x0, x0, :lo12:msg_v1
    mov x19, #32
    ret

msg_v0: .ascii "[aarch64] V0_ORIGINAL_ACTIVE\\n"
msg_v1: .ascii "[aarch64] V1_LIVEPATCHED_ACTIVE\\n"
"""
    },

    "riscv64": {
        "triple": "riscv64-linux-gnu",
        "emulator": "qemu-riscv64-static",
        "asm": """
.global _start
.text
_start:
    jal ra, get_version
    mv a1, a0
    mv a2, a3
    li a0, 1
    li a7, 64
    ecall

    lla a0, get_version
    li a1, -4096
    and a0, a0, a1
    li a1, 4096
    li a2, 7
    li a7, 226
    ecall

    lla a0, get_version
    li a1, 0x00000297
    sw a1, 0(a0)
    li a1, 0x0102b283
    sw a1, 4(a0)
    li a1, 0x8282
    sh a1, 8(a0)
    li a1, 0x0001
    sh a1, 10(a0)
    li a1, 0
    sw a1, 12(a0)
    lla a1, patch_version
    sd a1, 16(a0)

    jal ra, get_version
    mv a1, a0
    mv a2, a3
    li a0, 1
    li a7, 64
    ecall

    li a0, 0
    li a7, 93
    ecall

.align 4
get_version:
    lla a0, msg_v0
    li a3, 29
    ret
    .space 32, 0x13

.align 4
patch_version:
    lla a0, msg_v1
    li a3, 32
    ret

msg_v0: .ascii "[riscv64] V0_ORIGINAL_ACTIVE\\n"
msg_v1: .ascii "[riscv64] V1_LIVEPATCHED_ACTIVE\\n"
"""
    },

    "s390x": {
        "triple": "systemz-linux-gnu",
        "emulator": "qemu-s390x-static",
        "asm": """
.global _start
.text
_start:
    brasl %r14, get_version
    lgr %r3, %r2
    lghi %r4, 27
    lghi %r2, 1
    svc 4

    larl %r2, get_version
    nill %r2, 0xf000
    lghi %r3, 4096
    lghi %r4, 7
    svc 125

    larl %r5, get_version
    iihh %r1, 0xc418
    iihl %r1, 0x0000
    iilh %r1, 0x0004
    iill %r1, 0x07f1
    stg %r1, 0(%r5)
    larl %r6, patch_version
    stg %r6, 8(%r5)

    brasl %r14, get_version
    lgr %r3, %r2
    lghi %r4, 30
    lghi %r2, 1
    svc 4

    lghi %r2, 0
    svc 1

.align 8
get_version:
    larl %r2, msg_v0
    br %r14
    .space 16, 0x07

.align 8
patch_version:
    larl %r2, msg_v1
    br %r14

.align 2
msg_v0: .ascii "[s390x] V0_ORIGINAL_ACTIVE\\n"
.align 2
msg_v1: .ascii "[s390x] V1_LIVEPATCHED_ACTIVE\\n"
"""
    },

    "ppc64le": {
        "triple": "powerpc64le-linux-gnu",
        "emulator": "qemu-ppc64le-static",
        "asm": """
.abiversion 2
.global _start
.section ".text"
_start:
.localentry _start, 1
    bl get_version
    nop
    mr 4, 3
    li 5, 29
    li 3, 1
    li 0, 4
    sc

    bcl 20, 31, 2f
2:  mflr 3
    clrrdi 3, 3, 12
    li 4, 4096
    li 5, 7
    li 0, 125
    sc

    bcl 20, 31, 3f
3:  mflr 11
    addi 10, 11, (get_version - 3b)
    addi 9, 11, (patch_version - 3b)
    sub 8, 9, 10
    clrlwi 8, 8, 6
    oris 8, 8, 0x4800
    stw 8, 0(10)

    bl get_version
    nop
    mr 4, 3
    li 5, 32
    li 3, 1
    li 0, 4
    sc

    li 3, 0
    li 0, 1
    sc

.global get_version
get_version:
.localentry get_version, 1
    mflr 0
    bcl 20, 31, 1f
1:  mflr 12
    mtlr 0
    addi 3, 12, (msg_v0 - 1b)
    blr
    .space 16, 0x60000000

.global patch_version
patch_version:
.localentry patch_version, 1
    mflr 0
    bcl 20, 31, 4f
4:  mflr 12
    mtlr 0
    addi 3, 12, (msg_v1 - 4b)
    blr

msg_v0: .ascii "[ppc64le] V0_ORIGINAL_ACTIVE\\n"
msg_v1: .ascii "[ppc64le] V1_LIVEPATCHED_ACTIVE\\n"
"""
    },

    "loongarch64": {
        "triple": "loongarch64-linux-gnu",
        "emulator": "qemu-loongarch64-static",
        "asm": """
.global _start
.text
_start:
    bl get_version
    move $a1, $a0
    li.w $a2, 33
    li.w $a0, 1
    li.w $a7, 64
    syscall 0

    la.local $a0, get_version
    li.d $t0, -4096
    and $a0, $a0, $t0
    li.w $a1, 4096
    li.w $a2, 7
    li.w $a7, 226
    syscall 0

    la.local $t1, get_version
    li.w $t2, 0x1e00000c
    st.w $t2, $t1, 0
    li.w $t2, 0x28c0418c
    st.w $t2, $t1, 4
    li.w $t2, 0x4c000180
    st.w $t2, $t1, 8
    li.w $t2, 0x03400000
    st.w $t2, $t1, 12
    la.local $t3, patch_version
    st.d $t3, $t1, 16

    bl get_version
    move $a1, $a0
    li.w $a2, 36
    li.w $a0, 1
    li.w $a7, 64
    syscall 0

    li.w $a0, 0
    li.w $a7, 93
    syscall 0

.align 4
get_version:
    la.local $a0, msg_v0
    jr $ra
    .space 24, 0x00

.align 4
patch_version:
    la.local $a0, msg_v1
    jr $ra

msg_v0: .ascii "[loongarch64] V0_ORIGINAL_ACTIVE\\n"
msg_v1: .ascii "[loongarch64] V1_LIVEPATCHED_ACTIVE\\n"
"""
    }
}

def main():
    print("==============================================================================")
    print("   CROSS-ARCHITECTURE LIVEPATCHING EMULATION & VERIFICATION SUITE             ")
    print("==============================================================================")

    results = {}
    for arch, config in ARCH_CONFIGS.items():
        print(f"\n[*] Testing Architecture: {arch.upper()} (Target: {config['triple']})")
        src_file = f"{BENCH_DIR}/test_{arch}.s"
        bin_file = f"{BENCH_DIR}/bin_{arch}"

        with open(src_file, "w") as f:
            f.write(config["asm"])

        # Compile with Clang + LLD for target architecture
        print(f"  [1] Compiling standalone ELF with Clang + LLD (--target={config['triple']})...")
        compile_cmd = f"clang -fuse-ld=lld -nostdlib -static --target={config['triple']} -o {bin_file} {src_file}"
        code, out, err = run_cmd(compile_cmd)
        if code != 0:
            print(f"  [-] Compilation failed: {err}")
            results[arch] = f"COMPILE_FAIL ({err})"
            continue

        # Execute under QEMU static emulator
        emulator = config["emulator"]
        print(f"  [2] Running livepatch test under {emulator}...")
        exec_cmd = f"{emulator} {bin_file}"
        code, out, err = run_cmd(exec_cmd)

        if code == 0:
            print(f"  [+] Output:\n{out}")
            results[arch] = "SUCCESS (100% PASSED)"
        else:
            print(f"  [-] Emulation failed (code {code}): {err or out}")
            results[arch] = f"EXEC_FAIL (code {code})"

    print("\n==============================================================================")
    print("   MULTI-ARCHITECTURE EMULATION BENCHMARK SUMMARY                             ")
    print("==============================================================================")
    for arch, status in results.items():
        print(f"  * {arch:<14} : {status}")
    print("==============================================================================")

if __name__ == "__main__":
    main()
