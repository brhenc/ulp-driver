
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

msg_v0: .ascii "[aarch64] V0_ORIGINAL_ACTIVE\n"
msg_v1: .ascii "[aarch64] V1_LIVEPATCHED_ACTIVE\n"
