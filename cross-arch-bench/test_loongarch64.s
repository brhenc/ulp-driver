
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

msg_v0: .ascii "[loongarch64] V0_ORIGINAL_ACTIVE\n"
msg_v1: .ascii "[loongarch64] V1_LIVEPATCHED_ACTIVE\n"
