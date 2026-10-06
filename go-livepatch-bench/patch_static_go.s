.global _start
.text
_start:
    lea msg(%rip), %rax
    mov $30, %rbx
    ret
msg:
    .ascii "LIVEPATCHED_STATIC_GO_SERVICE"
