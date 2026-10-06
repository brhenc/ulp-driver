
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

msg_v0: .ascii "[x86_64] V0_ORIGINAL_ACTIVE\n"
msg_v1: .ascii "[x86_64] V1_LIVEPATCHED_ACTIVE\n"
