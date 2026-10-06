
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

msg_v0: .ascii "[riscv64] V0_ORIGINAL_ACTIVE\n"
msg_v1: .ascii "[riscv64] V1_LIVEPATCHED_ACTIVE\n"
