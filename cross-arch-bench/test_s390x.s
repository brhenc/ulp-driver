
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
msg_v0: .ascii "[s390x] V0_ORIGINAL_ACTIVE\n"
.align 2
msg_v1: .ascii "[s390x] V1_LIVEPATCHED_ACTIVE\n"
