
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

msg_v0: .ascii "[ppc64le] V0_ORIGINAL_ACTIVE\n"
msg_v1: .ascii "[ppc64le] V1_LIVEPATCHED_ACTIVE\n"
