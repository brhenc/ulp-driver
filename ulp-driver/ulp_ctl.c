#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <signal.h>
#include <elf.h>
#include <limits.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include "ulp_uapi.h"

static void print_usage(const char *prog)
{
    fprintf(stderr, "Usage: %s [--arm[=TTL]] <command> [args]\n\n", prog);
    fprintf(stderr, "Commands:\n");
    fprintf(stderr, "  list\n");
    fprintf(stderr, "  apply <pid> <binary>:<symbol> <patch.so>:<symbol> [patch_name]\n");
    fprintf(stderr, "                 resolve both symbols (patch.so must already be injected with ulp_inject)\n");
    fprintf(stderr, "  apply <pid> <patch_name> <func_name> <target_hex_vaddr> <patch_hex_vaddr> [func_len] [futex_hex_vaddr]\n");
    fprintf(stderr, "  revert <pid> <target_hex_vaddr>\n");
    fprintf(stderr, "  add-rule <bin_path> <patch_name> <func_name> <target_offset_hex> <patch_vaddr_hex> [func_len] [match_uid] [global_scope]\n");
    fprintf(stderr, "  del-rule <bin_path> <target_offset_hex>\n");
    fprintf(stderr, "  list-rules\n");
    fprintf(stderr, "  set-override <bin_path> [ttl_seconds]\n");
    fprintf(stderr, "  clear-override\n");
    fprintf(stderr, "  arm [TTL]      open a maintenance window and hold it until TTL expires or Ctrl-C\n");
    fprintf(stderr, "  disarm         close any maintenance window\n\n");
    fprintf(stderr, "Unless the driver is loaded with dev_mode=1, applying a patch requires an armed\n");
    fprintf(stderr, "maintenance window (root only). --arm arms one for this invocation; the driver\n");
    fprintf(stderr, "relocks automatically when ulp_ctl exits. TTL defaults to 60s (max 300s).\n");
}

/* Arm or disarm the maintenance window. Arming is bound to this fd: closing it relocks the driver. */
static int send_arm_cmd(int fd, uint32_t cmd_type, uint32_t ttl)
{
    struct ulp_cmd_v1 cmd;

    memset(&cmd, 0, sizeof(cmd));
    cmd.size = sizeof(cmd);
    cmd.cmd_type = cmd_type;
    cmd.ttl_seconds = ttl;
    if (write(fd, &cmd, sizeof(cmd)) < 0) {
        perror(cmd_type == ULP_CMD_ARM ? "Failed to arm /dev/ulp" : "Failed to disarm /dev/ulp");
        return -1;
    }
    return 0;
}

struct sym_loc {
    uint64_t vaddr;     /* runtime address in the target process */
    uint64_t size;      /* st_size from the symbol table */
};

/* Look up a defined function symbol in an ELF64 file: .symtab first, then .dynsym. */
static int elf_find_func(const char *path, const char *name, uint64_t *value, uint64_t *size,
                         int *is_pie, uint64_t *min_vaddr)
{
    struct stat st;
    int fd, ret = -1;
    uint8_t *map;

    fd = open(path, O_RDONLY);
    if (fd < 0 || fstat(fd, &st) < 0) {
        perror(path);
        if (fd >= 0)
            close(fd);
        return -1;
    }
    map = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);
    if (map == MAP_FAILED) {
        perror("mmap");
        return -1;
    }

    Elf64_Ehdr *eh = (Elf64_Ehdr *)map;
    if ((size_t)st.st_size < sizeof(*eh) || memcmp(eh->e_ident, ELFMAG, SELFMAG) != 0 ||
        eh->e_ident[EI_CLASS] != ELFCLASS64 || eh->e_machine != EM_X86_64 ||
        eh->e_shoff + (uint64_t)eh->e_shnum * sizeof(Elf64_Shdr) > (uint64_t)st.st_size) {
        fprintf(stderr, "%s: not a valid x86_64 ELF64 file\n", path);
        goto out;
    }
    *is_pie = (eh->e_type == ET_DYN);

    Elf64_Phdr *ph = (Elf64_Phdr *)(map + eh->e_phoff);
    *min_vaddr = UINT64_MAX;
    for (int i = 0; i < eh->e_phnum; i++)
        if (ph[i].p_type == PT_LOAD && ph[i].p_vaddr < *min_vaddr)
            *min_vaddr = ph[i].p_vaddr;
    *min_vaddr &= ~(uint64_t)(sysconf(_SC_PAGESIZE) - 1);

    Elf64_Shdr *sh = (Elf64_Shdr *)(map + eh->e_shoff);
    uint32_t want[2] = { SHT_SYMTAB, SHT_DYNSYM };
    for (int pass = 0; pass < 2 && ret < 0; pass++) {
        for (int i = 0; i < eh->e_shnum && ret < 0; i++) {
            if (sh[i].sh_type != want[pass] || sh[i].sh_link >= eh->e_shnum)
                continue;
            Elf64_Sym *syms = (Elf64_Sym *)(map + sh[i].sh_offset);
            const char *strtab = (const char *)(map + sh[sh[i].sh_link].sh_offset);
            uint64_t n = sh[i].sh_size / sizeof(Elf64_Sym);
            for (uint64_t j = 0; j < n; j++) {
                if (ELF64_ST_TYPE(syms[j].st_info) != STT_FUNC || syms[j].st_shndx == SHN_UNDEF)
                    continue;
                if (syms[j].st_name >= sh[sh[i].sh_link].sh_size)
                    continue;
                if (strcmp(strtab + syms[j].st_name, name) == 0) {
                    *value = syms[j].st_value;
                    *size = syms[j].st_size;
                    ret = 0;
                    break;
                }
            }
        }
    }
    if (ret < 0)
        fprintf(stderr, "%s: function symbol '%s' not found\n", path, name);
out:
    munmap(map, st.st_size);
    return ret;
}

/* Resolve "<file>:<symbol>" to a runtime address in process pid. */
static int resolve_spec(pid_t pid, const char *spec, char *sym_out, size_t sym_len, struct sym_loc *loc)
{
    char file[PATH_MAX], real[PATH_MAX], maps_path[64], line[PATH_MAX + 128];
    const char *colon = strrchr(spec, ':');
    uint64_t value, size, min_vaddr, start = 0;
    int is_pie, found = 0;
    FILE *f;

    if (!colon || colon == spec || !colon[1] || (size_t)(colon - spec) >= sizeof(file)) {
        fprintf(stderr, "Expected <file>:<symbol>, got '%s'\n", spec);
        return -1;
    }
    memcpy(file, spec, colon - spec);
    file[colon - spec] = '\0';
    snprintf(sym_out, sym_len, "%s", colon + 1);
    if (!realpath(file, real)) {
        perror(file);
        return -1;
    }
    if (elf_find_func(real, colon + 1, &value, &size, &is_pie, &min_vaddr) < 0)
        return -1;

    snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);
    f = fopen(maps_path, "r");
    if (!f) {
        perror(maps_path);
        return -1;
    }
    while (fgets(line, sizeof(line), f)) {
        unsigned long lo, hi, off;
        char path[PATH_MAX];

        path[0] = '\0';
        if (sscanf(line, "%lx-%lx %*s %lx %*s %*s %4095[^\n]", &lo, &hi, &off, path) < 3)
            continue;
        if (off == 0 && strcmp(path, real) == 0) {
            start = lo;
            found = 1;
            break;
        }
    }
    fclose(f);
    if (!found) {
        fprintf(stderr, "%s is not mapped in PID %d%s\n", real, pid,
                is_pie ? " (inject the patch library first with ulp_inject)" : "");
        return -1;
    }

    loc->vaddr = is_pie ? (start - min_vaddr) + value : value;
    loc->size = size;
    return 0;
}

static volatile sig_atomic_t g_stop;

static void on_signal(int sig)
{
    (void)sig;
    g_stop = 1;
}

int main(int argc, char **argv)
{
    const char *prog = argv[0];
    int arm = 0;
    uint32_t arm_ttl = 0;

    if (argc > 1 && strncmp(argv[1], "--arm", 5) == 0 && (argv[1][5] == '\0' || argv[1][5] == '=')) {
        arm = 1;
        if (argv[1][5] == '=')
            arm_ttl = (uint32_t)strtoul(argv[1] + 6, NULL, 0);
        argv++;
        argc--;
    }
    argv[0] = (char *)prog;

    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }

    const char *action = argv[1];
    int fd = open("/dev/ulp", O_RDWR);
    if (fd < 0) {
        perror("Failed to open /dev/ulp");
        return 1;
    }

    if (arm && send_arm_cmd(fd, ULP_CMD_ARM, arm_ttl) < 0) {
        close(fd);
        return 1;
    }

    if (strcmp(action, "list") == 0) {
        struct ulp_list_req lreq;
        memset(&lreq, 0, sizeof(lreq));

        if (ioctl(fd, ULP_IOC_LIST_PATCHES, &lreq) < 0) {
            perror("ioctl(ULP_IOC_LIST_PATCHES) failed");
            close(fd);
            return 1;
        }

        printf("%-7s %-6s %-16s %-24s %-24s %-18s %-18s %s\n",
               "PID", "UID", "PROCESS", "PATCH_NAME", "FUNCTION", "ORIG_ADDR", "PATCH_ADDR", "STATUS");
        printf("----------------------------------------------------------------------------------------------------------------------------\n");

        if (lreq.count == 0) {
            printf("No active userspace livepatches accessible to current user.\n");
        } else {
            for (uint32_t i = 0; i < lreq.count; i++) {
                struct ulp_patch_info *p = &lreq.entries[i];
                printf("%-7u %-6u %-16s %-24s %-24s 0x%016llx 0x%016llx %s\n",
                       p->target_pid,
                       p->owner_uid,
                       p->comm,
                       p->patch_name,
                       p->func_name,
                       (unsigned long long)p->target_vaddr,
                       (unsigned long long)p->patch_vaddr,
                       p->enabled ? "ACTIVE (1)" : "DISABLED (0)");
            }
        }
    } else if (strcmp(action, "apply") == 0 && (argc == 5 || argc == 6) &&
               strchr(argv[3], ':') && strchr(argv[4], ':')) {
        struct ulp_patch_req req;
        struct sym_loc target, patch;
        char tsym[ULP_NAME_MAX], psym[ULP_NAME_MAX];

        memset(&req, 0, sizeof(req));
        req.target_pid = (pid_t)atoi(argv[2]);
        if (resolve_spec(req.target_pid, argv[3], tsym, sizeof(tsym), &target) < 0 ||
            resolve_spec(req.target_pid, argv[4], psym, sizeof(psym), &patch) < 0) {
            close(fd);
            return 1;
        }
        if (target.size < 5) {
            fprintf(stderr, "Refusing: '%s' has %s size (%llu bytes); at least 5 bytes are needed for a jump\n",
                    tsym, target.size ? "too small a" : "an unknown", (unsigned long long)target.size);
            close(fd);
            return 1;
        }
        snprintf(req.patch_name, ULP_NAME_MAX, "%s", argc == 6 ? argv[5] : psym);
        snprintf(req.func_name, ULP_NAME_MAX, "%s", tsym);
        req.target_vaddr = target.vaddr;
        req.patch_vaddr = patch.vaddr;
        req.func_len = (uint32_t)target.size;
        printf("[ulp_ctl] Resolved %s = 0x%llx (%u bytes), %s = 0x%llx\n", tsym,
               (unsigned long long)req.target_vaddr, req.func_len, psym, (unsigned long long)req.patch_vaddr);

        if (ioctl(fd, ULP_IOC_APPLY_PATCH, &req) < 0) {
            int err = errno;
            perror("ioctl(ULP_IOC_APPLY_PATCH) failed");
            if (err == EPERM && !arm)
                fprintf(stderr, "Hint: the driver may be locked. Rerun as root with --arm, or load the driver with dev_mode=1 for testing (see dmesg).\n");
            if (err == ERANGE)
                fprintf(stderr, "Hint: '%s' is under 16 bytes, so only a 5-byte relative jump fits, and the patch is more than +/-2 GB away. This function cannot be patched safely yet.\n", tsym);
            close(fd);
            return 1;
        }
        printf("[ulp_ctl] SUCCESS: Kernel applied livepatch '%s::%s' to PID %d at 0x%llx -> 0x%llx (len=%u)\n",
               req.patch_name, req.func_name, req.target_pid,
               (unsigned long long)req.target_vaddr, (unsigned long long)req.patch_vaddr, req.func_len);
    } else if (strcmp(action, "apply") == 0) {
        if (argc < 7) {
            print_usage(argv[0]);
            close(fd);
            return 1;
        }

        struct ulp_patch_req req;
        memset(&req, 0, sizeof(req));
        req.target_pid = (pid_t)atoi(argv[2]);
        strncpy(req.patch_name, argv[3], ULP_NAME_MAX - 1);
        strncpy(req.func_name, argv[4], ULP_NAME_MAX - 1);
        req.target_vaddr = strtoull(argv[5], NULL, 16);
        req.patch_vaddr = strtoull(argv[6], NULL, 16);
        if (argc > 7) {
            req.func_len = (uint32_t)strtoul(argv[7], NULL, 0);
        }
        if (argc > 8) {
            req.futex_vaddr = strtoull(argv[8], NULL, 16);
        }

        if (ioctl(fd, ULP_IOC_APPLY_PATCH, &req) < 0) {
            int err = errno;
            perror("ioctl(ULP_IOC_APPLY_PATCH) failed");
            if (err == EPERM && !arm)
                fprintf(stderr, "Hint: the driver may be locked. Rerun as root with --arm, or load the driver with dev_mode=1 for testing (see dmesg).\n");
            close(fd);
            return 1;
        }
        printf("[ulp_ctl] SUCCESS: Kernel applied livepatch '%s::%s' to PID %d at 0x%llx -> 0x%llx (len=%u)\n",
               req.patch_name, req.func_name, req.target_pid,
               (unsigned long long)req.target_vaddr, (unsigned long long)req.patch_vaddr, req.func_len);
    } else if (strcmp(action, "revert") == 0) {
        if (argc < 4) {
            print_usage(argv[0]);
            close(fd);
            return 1;
        }

        struct ulp_patch_req req;
        memset(&req, 0, sizeof(req));
        req.target_pid = (pid_t)atoi(argv[2]);
        req.target_vaddr = strtoull(argv[3], NULL, 16);

        if (ioctl(fd, ULP_IOC_REVERT_PATCH, &req) < 0) {
            perror("ioctl(ULP_IOC_REVERT_PATCH) failed");
            close(fd);
            return 1;
        }
        printf("[ulp_ctl] SUCCESS: Kernel reverted livepatch for PID %d at 0x%llx\n",
               req.target_pid, (unsigned long long)req.target_vaddr);
    } else if (strcmp(action, "add-rule") == 0) {
        if (argc < 7) {
            fprintf(stderr, "Usage: %s add-rule <bin_path> <patch_name> <func_name> <target_offset_hex> <patch_vaddr_hex> [func_len] [match_uid] [global_scope]\n", argv[0]);
            close(fd);
            return 1;
        }

        struct ulp_kernel_rule_req rreq;
        memset(&rreq, 0, sizeof(rreq));
        strncpy(rreq.binary_path, argv[2], sizeof(rreq.binary_path) - 1);
        strncpy(rreq.patch_name, argv[3], sizeof(rreq.patch_name) - 1);
        strncpy(rreq.func_name, argv[4], sizeof(rreq.func_name) - 1);
        rreq.target_offset = strtoull(argv[5], NULL, 16);
        rreq.patch_vaddr = strtoull(argv[6], NULL, 16);
        rreq.func_len = (argc > 7) ? (uint32_t)strtoul(argv[7], NULL, 0) : 16;
        rreq.match_uid = (argc > 8) ? (uint32_t)atoi(argv[8]) : (uint32_t)-1;
        rreq.global_scope = (argc > 9) ? (uint8_t)atoi(argv[9]) : 1;

        /* Build safe return stub or 16-byte CET absolute trampoline / 5-byte relative jump */
        if (rreq.patch_vaddr == 0) {
            rreq.tramp_type = ULP_TRAMP_ABS16;
            rreq.patch_bytes[0] = 0xF3; rreq.patch_bytes[1] = 0x0F; rreq.patch_bytes[2] = 0x1E; rreq.patch_bytes[3] = 0xFA; /* endbr64 */
            rreq.patch_bytes[4] = 0x31; rreq.patch_bytes[5] = 0xC0; /* xor %eax, %eax */
            rreq.patch_bytes[6] = 0xC3; /* ret */
            memset(&rreq.patch_bytes[7], 0x90, 9); /* nop padding */
        } else if (rreq.func_len < 16) {
            rreq.tramp_type = ULP_TRAMP_REL5;
            rreq.patch_bytes[0] = 0xE9; /* jmp rel32 (will be displacement patched) */
        } else {
            rreq.tramp_type = ULP_TRAMP_ABS16;
            rreq.patch_bytes[0] = 0xF3; rreq.patch_bytes[1] = 0x0F; rreq.patch_bytes[2] = 0x1E; rreq.patch_bytes[3] = 0xFA; /* endbr64 */
            rreq.patch_bytes[4] = 0x48; rreq.patch_bytes[5] = 0xB8; /* movabs <patch_vaddr>, %rax */
            memcpy(&rreq.patch_bytes[6], &rreq.patch_vaddr, 8);
            rreq.patch_bytes[14] = 0xFF; rreq.patch_bytes[15] = 0xE0; /* jmpq *%rax */
        }

        if (ioctl(fd, ULP_IOC_ADD_RULE, &rreq) < 0) {
            perror("ioctl(ULP_IOC_ADD_RULE) failed");
            close(fd);
            return 1;
        }
        printf("[ulp_ctl] SUCCESS: Registered in-kernel persistent rule for '%s' -> 0x%llx [%s::%s] (Global: %u)\n",
               rreq.binary_path, (unsigned long long)rreq.target_offset, rreq.patch_name, rreq.func_name, rreq.global_scope);
    } else if (strcmp(action, "del-rule") == 0) {
        if (argc < 4) {
            fprintf(stderr, "Usage: %s del-rule <bin_path> <target_offset_hex>\n", argv[0]);
            close(fd);
            return 1;
        }

        struct ulp_kernel_rule_req rreq;
        memset(&rreq, 0, sizeof(rreq));
        strncpy(rreq.binary_path, argv[2], sizeof(rreq.binary_path) - 1);
        rreq.target_offset = strtoull(argv[3], NULL, 16);

        if (ioctl(fd, ULP_IOC_DEL_RULE, &rreq) < 0) {
            perror("ioctl(ULP_IOC_DEL_RULE) failed");
            close(fd);
            return 1;
        }
        printf("[ulp_ctl] SUCCESS: Deleted persistent rule for '%s' at offset 0x%llx\n",
               rreq.binary_path, (unsigned long long)rreq.target_offset);
    } else if (strcmp(action, "list-rules") == 0) {
        struct ulp_kernel_rules_list rlist;
        memset(&rlist, 0, sizeof(rlist));

        if (ioctl(fd, ULP_IOC_LIST_RULES, &rlist) < 0) {
            perror("ioctl(ULP_IOC_LIST_RULES) failed");
            close(fd);
            return 1;
        }

        printf("\n=== ACTIVE IN-KERNEL PERSISTENT LIVEPATCH RULES ===\n");
        printf("%-30s %-20s %-20s %-18s %-18s %-6s %-6s\n",
               "BINARY PATH", "PATCH_NAME", "FUNCTION", "TARGET_OFFSET", "PATCH_VADDR", "UID", "GLOBAL");
        printf("--------------------------------------------------------------------------------------------------------------------\n");
        if (rlist.count == 0) {
            printf("No persistent kernel rules registered.\n");
        } else {
            for (uint32_t i = 0; i < rlist.count; i++) {
                struct ulp_kernel_rule_req *r = &rlist.entries[i];
                printf("%-30s %-20s %-20s 0x%016llx 0x%016llx %-6u %-6u\n",
                       r->binary_path, r->patch_name, r->func_name,
                       (unsigned long long)r->target_offset, (unsigned long long)r->patch_vaddr,
                       r->match_uid, r->global_scope);
            }
        }
        printf("--------------------------------------------------------------------------------------------------------------------\n\n");
    } else if (strcmp(action, "set-override") == 0) {
        if (argc < 3) {
            fprintf(stderr, "Usage: %s set-override <bin_path> [ttl_seconds]\n", argv[0]);
            close(fd);
            return 1;
        }

        struct ulp_override_req oreq;
        memset(&oreq, 0, sizeof(oreq));
        oreq.magic[0] = ULP_OVERRIDE_MAGIC_0;
        oreq.magic[1] = ULP_OVERRIDE_MAGIC_1;
        oreq.magic[2] = ULP_OVERRIDE_MAGIC_2;
        oreq.magic[3] = ULP_OVERRIDE_MAGIC_3;
        strncpy(oreq.binary_path, argv[2], sizeof(oreq.binary_path) - 1);
        oreq.ttl_seconds = (argc > 3) ? (uint32_t)atoi(argv[3]) : 300;

        if (ioctl(fd, ULP_IOC_SET_OVERRIDE, &oreq) < 0) {
            perror("ioctl(ULP_IOC_SET_OVERRIDE) failed");
            close(fd);
            return 1;
        }
        printf("[ulp_ctl] SUCCESS: Emergency kernel override activated for '%s' (TTL: %u s)\n",
               oreq.binary_path, oreq.ttl_seconds);
    } else if (strcmp(action, "clear-override") == 0) {
        if (ioctl(fd, ULP_IOC_CLEAR_OVERRIDE) < 0) {
            perror("ioctl(ULP_IOC_CLEAR_OVERRIDE) failed");
            close(fd);
            return 1;
        }
        printf("[ulp_ctl] SUCCESS: Emergency kernel override cleared. Livepatching active.\n");
    } else if (strcmp(action, "arm") == 0) {
        uint32_t ttl = (argc > 2) ? (uint32_t)strtoul(argv[2], NULL, 0) : 60;

        if (ttl > 300)
            ttl = 300;
        if (send_arm_cmd(fd, ULP_CMD_ARM, ttl) < 0) {
            close(fd);
            return 1;
        }
        signal(SIGINT, on_signal);
        signal(SIGTERM, on_signal);
        signal(SIGALRM, on_signal);
        alarm(ttl);
        printf("[ulp_ctl] Driver ARMED for %u s. Press Ctrl-C to disarm early.\n", ttl);
        fflush(stdout);
        while (!g_stop)
            pause();
        printf("[ulp_ctl] Maintenance window closed; driver locked.\n");
    } else if (strcmp(action, "disarm") == 0) {
        if (send_arm_cmd(fd, ULP_CMD_DISARM, 0) < 0) {
            close(fd);
            return 1;
        }
        printf("[ulp_ctl] Driver disarmed and locked.\n");
    } else {
        print_usage(argv[0]);
        close(fd);
        return 1;
    }

    close(fd);
    return 0;
}
