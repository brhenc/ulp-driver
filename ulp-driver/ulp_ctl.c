#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <string.h>
#include <stdint.h>
#include "ulp_uapi.h"

static void print_usage(const char *prog)
{
    fprintf(stderr, "Usage:\n");
    fprintf(stderr, "  %s list\n", prog);
    fprintf(stderr, "  %s apply <pid> <patch_name> <func_name> <target_hex_vaddr> <patch_hex_vaddr> [func_len] [futex_hex_vaddr]\n", prog);
    fprintf(stderr, "  %s revert <pid> <target_hex_vaddr>\n", prog);
}

int main(int argc, char **argv)
{
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
            perror("ioctl(ULP_IOC_APPLY_PATCH) failed");
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
    } else {
        print_usage(argv[0]);
        close(fd);
        return 1;
    }

    close(fd);
    return 0;
}
