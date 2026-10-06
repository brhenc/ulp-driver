#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <elf.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/mman.h>
#include <dlfcn.h>
#include <stdint.h>
#include <errno.h>

/* ptrace-based injector for shared objects (dynamic binaries) and raw code (static binaries).
 * Stops the target with ptrace while injecting.
 * - Dynamic Binaries: Non-destructive private-stack dlopen frame.
 * - Static Binaries: Injects remote sys_mmap to allocate executable page for raw code.
 * - Universal PIE & Non-PIE ELF binary parsing.
 */

static int has_dynamic_libc(pid_t pid)
{
    char maps_path[64];
    snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);
    FILE *f = fopen(maps_path, "r");
    if (!f) return 0;

    char line[512];
    int dynamic = 0;
    while (fgets(line, sizeof(line), f)) {
        if (strstr(line, "libc.so") || strstr(line, "ld-linux") || strstr(line, "libdl.so")) {
            dynamic = 1;
            break;
        }
    }
    fclose(f);
    return dynamic;
}

static uintptr_t get_remote_symbol(pid_t pid, const char *lib_name, const char *sym_name)
{
    char maps_path[64];
    snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);
    FILE *f = fopen(maps_path, "r");
    if (!f) return 0;

    char line[512];
    uintptr_t remote_base = 0;
    while (fgets(line, sizeof(line), f)) {
        if (strstr(line, lib_name)) {
            remote_base = (uintptr_t)strtoull(line, NULL, 16);
            break;
        }
    }
    fclose(f);
    if (!remote_base) return 0;

    void *local_handle = dlopen(lib_name, RTLD_LAZY | RTLD_NOLOAD);
    if (!local_handle) local_handle = dlopen(lib_name, RTLD_LAZY);
    if (!local_handle) return 0;

    void *local_sym = dlsym(local_handle, sym_name);
    if (!local_sym) return 0;

    Dl_info info;
    if (!dladdr(local_sym, &info)) return 0;

    uintptr_t local_base = (uintptr_t)info.dli_fbase;
    uintptr_t offset = (uintptr_t)local_sym - local_base;
    return remote_base + offset;
}

/* Locate an INT3 (0xCC) instruction inside remote libc ELF */
static uintptr_t get_remote_int3_gadget(pid_t pid, const char *lib_name)
{
    char maps_path[64];
    snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);
    FILE *f = fopen(maps_path, "r");
    if (!f) return 0;

    char line[512];
    uintptr_t remote_base = 0;
    char path[256] = {0};
    while (fgets(line, sizeof(line), f)) {
        if (strstr(line, lib_name)) {
            remote_base = (uintptr_t)strtoull(line, NULL, 16);
            char *p = strchr(line, '/');
            if (p) {
                strncpy(path, p, sizeof(path) - 1);
                char *nl = strchr(path, '\n');
                if (nl) *nl = '\0';
            }
            break;
        }
    }
    fclose(f);
    if (!remote_base || !path[0]) return 0;

    int fd = open(path, O_RDONLY);
    if (fd < 0) return 0;

    Elf64_Ehdr ehdr;
    if (read(fd, &ehdr, sizeof(ehdr)) != sizeof(ehdr)) {
        close(fd);
        return 0;
    }

    lseek(fd, ehdr.e_phoff, SEEK_SET);
    Elf64_Phdr phdr;
    uintptr_t int3_vaddr = 0;

    for (int i = 0; i < ehdr.e_phnum; i++) {
        if (read(fd, &phdr, sizeof(phdr)) != sizeof(phdr)) break;
        if (phdr.p_type == PT_LOAD && (phdr.p_flags & PF_X)) {
            uint8_t *buf = malloc(phdr.p_filesz);
            if (!buf) break;
            lseek(fd, phdr.p_offset, SEEK_SET);
            if (read(fd, buf, phdr.p_filesz) == (ssize_t)phdr.p_filesz) {
                for (size_t k = 0; k < phdr.p_filesz; k++) {
                    if (buf[k] == 0xCC) {
                        int3_vaddr = remote_base + phdr.p_vaddr + k;
                        break;
                    }
                }
            }
            free(buf);
            if (int3_vaddr) break;
            lseek(fd, ehdr.e_phoff + (i + 1) * sizeof(phdr), SEEK_SET);
        }
    }
    close(fd);
    return int3_vaddr;
}

/* Locate a "syscall" (0x0F 0x05) instruction directly from target executable ELF */
static uintptr_t get_remote_syscall_gadget(pid_t pid)
{
    char exe_link[64];
    snprintf(exe_link, sizeof(exe_link), "/proc/%d/exe", pid);
    int fd = open(exe_link, O_RDONLY);
    if (fd < 0) return 0;

    Elf64_Ehdr ehdr;
    if (read(fd, &ehdr, sizeof(ehdr)) != sizeof(ehdr)) {
        close(fd);
        return 0;
    }

    uintptr_t aslr_base = 0;
    if (ehdr.e_type == ET_DYN) {
        char maps_path[64];
        snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);
        FILE *mf = fopen(maps_path, "r");
        if (mf) {
            char line[512];
            if (fgets(line, sizeof(line), mf)) {
                aslr_base = (uintptr_t)strtoull(line, NULL, 16);
            }
            fclose(mf);
        }
    }

    lseek(fd, ehdr.e_phoff, SEEK_SET);
    Elf64_Phdr phdr;
    uintptr_t sys_vaddr = 0;

    for (int i = 0; i < ehdr.e_phnum; i++) {
        if (read(fd, &phdr, sizeof(phdr)) != sizeof(phdr)) break;
        if (phdr.p_type == PT_LOAD && (phdr.p_flags & PF_X)) {
            uint8_t *buf = malloc(phdr.p_filesz);
            if (!buf) break;
            lseek(fd, phdr.p_offset, SEEK_SET);
            if (read(fd, buf, phdr.p_filesz) == (ssize_t)phdr.p_filesz) {
                for (size_t k = 0; k < phdr.p_filesz - 1; k++) {
                    if (buf[k] == 0x0F && buf[k+1] == 0x05) { /* syscall */
                        sys_vaddr = aslr_base + phdr.p_vaddr + k;
                        break;
                    }
                }
            }
            free(buf);
            if (sys_vaddr) break;
            lseek(fd, ehdr.e_phoff + (i + 1) * sizeof(phdr), SEEK_SET);
        }
    }
    close(fd);
    return sys_vaddr;
}

static uintptr_t inject_static_payload(pid_t target_pid, const uint8_t *code, size_t code_len)
{
    uintptr_t sys_gadget = get_remote_syscall_gadget(target_pid);
    if (!sys_gadget) {
        fprintf(stderr, "[-] Failed to find syscall gadget in target ELF for PID %d\n", target_pid);
        return 0;
    }

    if (ptrace(PTRACE_ATTACH, target_pid, NULL, NULL) < 0) {
        perror("[-] ptrace(PTRACE_ATTACH) failed");
        return 0;
    }

    int status;
    waitpid(target_pid, &status, 0);

    struct user_regs_struct old_regs, new_regs;
    struct user_fpregs_struct old_fpregs;
    if (ptrace(PTRACE_GETREGS, target_pid, NULL, &old_regs) < 0) {
        perror("[-] ptrace(PTRACE_GETREGS) failed");
        ptrace(PTRACE_DETACH, target_pid, NULL, NULL);
        return 0;
    }
    ptrace(PTRACE_GETFPREGS, target_pid, NULL, &old_fpregs);

    /* Allocate memory adjacent to executable text using MAP_FIXED_NOREPLACE loop */
    uintptr_t target_vaddr = (sys_gadget & ~0xFFFFF) + 0x300000;
    uintptr_t mmap_addr = 0;

    for (int attempt = 0; attempt < 16; attempt++) {
        uintptr_t try_addr = target_vaddr + (attempt * 0x100000);
        memcpy(&new_regs, &old_regs, sizeof(new_regs));
        new_regs.orig_rax = -1;
        new_regs.rax = 9; /* __NR_mmap */
        new_regs.rdi = try_addr;
        new_regs.rsi = 4096;
        new_regs.rdx = 7; /* PROT_READ|PROT_WRITE|PROT_EXEC */
        new_regs.r10 = 0x100022; /* MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED_NOREPLACE */
        new_regs.r8 = (uint64_t)-1;
        new_regs.r9 = 0;
        new_regs.rip = sys_gadget;

        ptrace(PTRACE_SETREGS, target_pid, NULL, &new_regs);
        ptrace(PTRACE_SYSCALL, target_pid, NULL, NULL);
        waitpid(target_pid, &status, 0);
        ptrace(PTRACE_SYSCALL, target_pid, NULL, NULL);
        waitpid(target_pid, &status, 0);

        struct user_regs_struct ret_regs;
        ptrace(PTRACE_GETREGS, target_pid, NULL, &ret_regs);
        if ((int64_t)ret_regs.rax > 0) {
            mmap_addr = (uintptr_t)ret_regs.rax;
            break;
        }
    }

    if ((int64_t)mmap_addr <= 0 && (int64_t)mmap_addr >= -4095) {
        fprintf(stderr, "[-] Remote sys_mmap failed with error: %ld\n", (long)mmap_addr);
        ptrace(PTRACE_SETREGS, target_pid, NULL, &old_regs);
        ptrace(PTRACE_SETFPREGS, target_pid, NULL, &old_fpregs);
        ptrace(PTRACE_DETACH, target_pid, NULL, NULL);
        return 0;
    }

    /* Write code payload into allocated page */
    for (size_t i = 0; i < code_len; i += 8) {
        uint64_t data = 0;
        memcpy(&data, code + i, (code_len - i < 8) ? (code_len - i) : 8);
        ptrace(PTRACE_POKEDATA, target_pid, (void *)(mmap_addr + i), (void *)data);
    }

    /* Restore original thread registers */
    ptrace(PTRACE_SETREGS, target_pid, NULL, &old_regs);
    ptrace(PTRACE_SETFPREGS, target_pid, NULL, &old_fpregs);
    ptrace(PTRACE_DETACH, target_pid, NULL, NULL);

    return mmap_addr;
}

int main(int argc, char **argv)
{
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <pid> <path_to_so_or_bin>\n", argv[0]);
        return 1;
    }

    pid_t target_pid = (pid_t)atoi(argv[1]);
    const char *path = argv[2];

    int is_dynamic = has_dynamic_libc(target_pid);

    if (!is_dynamic || strstr(path, ".bin")) {
        /* Static Binary / Raw Code Injection Mode */
        FILE *bf = fopen(path, "rb");
        if (!bf) {
            fprintf(stderr, "[-] Failed to open patch file: %s\n", path);
            return 1;
        }
        fseek(bf, 0, SEEK_END);
        long sz = ftell(bf);
        fseek(bf, 0, SEEK_SET);

        uint8_t *code = malloc(sz);
        if (!code || fread(code, 1, sz, bf) != (size_t)sz) {
            fprintf(stderr, "[-] Failed to read patch file bytes\n");
            if (code) free(code);
            fclose(bf);
            return 1;
        }
        fclose(bf);

        uintptr_t patch_addr = inject_static_payload(target_pid, code, sz);
        free(code);

        if (!patch_addr) {
            fprintf(stderr, "[-] Static injection failed for PID %d\n", target_pid);
            return 1;
        }

        printf("[ulp_inject] STATIC_INJECT_SUCCESS: target_patch_addr=0x%lx\n", (unsigned long)patch_addr);
        return 0;
    }

    /* Dynamic Binary Shared Object Injection Mode */
    uintptr_t remote_dlopen = get_remote_symbol(target_pid, "libc.so.6", "dlopen");
    if (!remote_dlopen) {
        remote_dlopen = get_remote_symbol(target_pid, "libc.so.6", "__libc_dlopen_mode");
    }
    if (!remote_dlopen) {
        remote_dlopen = get_remote_symbol(target_pid, "libdl.so.2", "dlopen");
    }

    if (!remote_dlopen) {
        fprintf(stderr, "[-] Failed to resolve remote dlopen symbol for PID %d\n", target_pid);
        return 1;
    }

    uintptr_t remote_int3 = get_remote_int3_gadget(target_pid, "libc.so.6");
    if (!remote_int3) {
        fprintf(stderr, "[-] Failed to find INT3 gadget in remote libc for PID %d\n", target_pid);
        return 1;
    }

    if (ptrace(PTRACE_ATTACH, target_pid, NULL, NULL) < 0) {
        perror("[-] ptrace(PTRACE_ATTACH) failed");
        return 1;
    }

    int status;
    waitpid(target_pid, &status, 0);

    struct user_regs_struct old_regs, new_regs;
    struct user_fpregs_struct old_fpregs;
    if (ptrace(PTRACE_GETREGS, target_pid, NULL, &old_regs) < 0) {
        perror("[-] ptrace(PTRACE_GETREGS) failed");
        ptrace(PTRACE_DETACH, target_pid, NULL, NULL);
        return 1;
    }
    ptrace(PTRACE_GETFPREGS, target_pid, NULL, &old_fpregs);

    /* Allocate argument string and fake stack frame on target thread's private stack */
    size_t len = strlen(path) + 1;
    uintptr_t str_addr = (old_regs.rsp - 512) & ~0xF;

    /* Write string to stack using POKEDATA */
    for (size_t i = 0; i < len; i += 8) {
        uint64_t data = 0;
        memcpy(&data, path + i, (len - i < 8) ? (len - i) : 8);
        if (ptrace(PTRACE_POKEDATA, target_pid, (void *)(str_addr + i), (void *)data) < 0) {
            perror("[-] ptrace(PTRACE_POKEDATA) failed writing string to stack");
        }
    }

    /* Place remote INT3 return address on stack */
    uintptr_t ret_addr_ptr = str_addr - 8;
    if (ptrace(PTRACE_POKEDATA, target_pid, (void *)ret_addr_ptr, (void *)remote_int3) < 0) {
        perror("[-] ptrace(PTRACE_POKEDATA) failed writing INT3 return address");
    }

    /* Set up execution state:
     * RIP = dlopen
     * RSP = ret_addr_ptr (points to remote_int3)
     * RDI = str_addr (path)
     * RSI = 2 (RTLD_NOW)
     */
    memcpy(&new_regs, &old_regs, sizeof(new_regs));
    new_regs.orig_rax = -1; /* Prevent kernel syscall restart from rolling back RIP by 2 bytes */
    new_regs.rax = 0;
    new_regs.rdi = str_addr;
    new_regs.rsi = 2; /* RTLD_NOW */
    new_regs.rip = remote_dlopen;
    new_regs.rsp = ret_addr_ptr;

    ptrace(PTRACE_SETREGS, target_pid, NULL, &new_regs);
    unsigned long sig = 0;
    while (1) {
        if (ptrace(PTRACE_CONT, target_pid, NULL, (void *)sig) < 0)
            break;
        if (waitpid(target_pid, &status, __WALL) < 0)
            break;
        if (WIFEXITED(status)) {
            fprintf(stderr, "[-] Target process EXITED with code %d\n", WEXITSTATUS(status));
            break;
        }
        if (WIFSIGNALED(status)) {
            fprintf(stderr, "[-] Target process KILLED by signal %d (%s)\n", WTERMSIG(status), strsignal(WTERMSIG(status)));
            break;
        }
        if (WIFSTOPPED(status)) {
            int stopsig = WSTOPSIG(status);
            if (stopsig == SIGTRAP)
                break;
            fprintf(stderr, "[*] Target process stopped by signal %d (%s)\n", stopsig, strsignal(stopsig));
            struct user_regs_struct cur_regs;
            ptrace(PTRACE_GETREGS, target_pid, NULL, &cur_regs);
            fprintf(stderr, "    Current RIP=0x%llx RSP=0x%llx RAX=0x%llx\n", cur_regs.rip, cur_regs.rsp, cur_regs.rax);
            sig = (unsigned long)stopsig;
        }
    }

    struct user_regs_struct end_regs;
    ptrace(PTRACE_GETREGS, target_pid, NULL, &end_regs);

    /* Restore original thread registers */
    ptrace(PTRACE_SETREGS, target_pid, NULL, &old_regs);
    ptrace(PTRACE_SETFPREGS, target_pid, NULL, &old_fpregs);
    ptrace(PTRACE_DETACH, target_pid, NULL, NULL);

    if (end_regs.rax == 0) {
        fprintf(stderr, "[-] Remote dlopen failed (returned NULL) in PID %d. RIP=0x%llx RAX=0x%llx RSP=0x%llx (remote_dlopen=0x%lx, int3=0x%lx)\n",
                target_pid, end_regs.rip, end_regs.rax, end_regs.rsp, remote_dlopen, remote_int3);
        return 1;
    }

    printf("[ulp_inject] SUCCESS: Injected %s into PID %d (handle=0x%llx)\n",
           path, target_pid, end_regs.rax);
    return 0;
}
