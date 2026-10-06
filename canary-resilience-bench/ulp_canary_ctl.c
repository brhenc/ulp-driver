#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <dlfcn.h>
#include <stdint.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <elf.h>

/*
 * ULP Canary & Resilience Controller
 * Controls livepatch injection, canary ratios, and fault registration for test targets.
 */

static void print_usage(const char *prog)
{
    printf("Usage:\n");
    printf("  %s inject <pid> <so_path>\n", prog);
    printf("  %s patch <pid> <target_vaddr_hex> <patch_vaddr_hex>\n", prog);
    printf("  %s revert <pid> <target_vaddr_hex> <orig_bytes_hex>\n", prog);
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }

    const char *action = argv[1];

    if (strcmp(action, "inject") == 0) {
        if (argc < 4) {
            fprintf(stderr, "Usage: %s inject <pid> <so_path>\n", argv[0]);
            return 1;
        }
        pid_t pid = atoi(argv[2]);
        const char *so_path = argv[3];

        char cmd[512];
        snprintf(cmd, sizeof(cmd), "/usr/local/bin/ulp_inject %d %s 2>/dev/null || ./ulp_inject %d %s 2>/dev/null || ../ulp-driver/ulp_inject %d %s",
                 pid, so_path, pid, so_path, pid, so_path);
        int ret = system(cmd);
        return ret == 0 ? 0 : 1;
    }

    if (strcmp(action, "patch") == 0) {
        if (argc < 4) {
            fprintf(stderr, "Usage: %s patch <pid> <target_vaddr_hex> <patch_vaddr_hex>\n", argv[0]);
            return 1;
        }
        pid_t target_pid = atoi(argv[2]);
        uintptr_t target_vaddr = strtoull(argv[3], NULL, 16);
        uintptr_t patch_vaddr = strtoull(argv[4], NULL, 16);

        /* Build 16-byte CET/IBT safe absolute jump trampoline:
         * 0xF3, 0x0F, 0x1E, 0xFA (endbr64)
         * 0x48, 0xB8, <8-byte patch_vaddr> (movabs patch_vaddr, %rax)
         * 0xFF, 0xE0 (jmpq *%rax)
         */
        uint8_t tramp[16];
        tramp[0] = 0xF3; tramp[1] = 0x0F; tramp[2] = 0x1E; tramp[3] = 0xFA;
        tramp[4] = 0x48; tramp[5] = 0xB8;
        memcpy(&tramp[6], &patch_vaddr, 8);
        tramp[14] = 0xFF; tramp[15] = 0xE0;

        if (ptrace(PTRACE_ATTACH, target_pid, NULL, NULL) < 0) {
            perror("ptrace attach failed");
            return 1;
        }
        int status;
        waitpid(target_pid, &status, 0);

        /* Read and save original 16 bytes */
        uint8_t orig[16];
        for (size_t i = 0; i < 16; i += 8) {
            long data = ptrace(PTRACE_PEEKTEXT, target_pid, (void *)(target_vaddr + i), NULL);
            memcpy(orig + i, &data, 8);
        }

        printf("[ulp_canary_ctl] Target: 0x%lx -> Patch: 0x%lx\n", target_vaddr, patch_vaddr);
        printf("[ulp_canary_ctl] Original bytes: ");
        for (int i = 0; i < 16; i++) printf("%02x ", orig[i]);
        printf("\n");

        /* Write 16-byte trampoline */
        for (size_t i = 0; i < 16; i += 8) {
            long data = 0;
            memcpy(&data, tramp + i, 8);
            if (ptrace(PTRACE_POKETEXT, target_pid, (void *)(target_vaddr + i), (void *)data) < 0) {
                perror("ptrace poketext failed");
                ptrace(PTRACE_DETACH, target_pid, NULL, NULL);
                return 1;
            }
        }

        ptrace(PTRACE_DETACH, target_pid, NULL, NULL);
        printf("[ulp_canary_ctl] Livepatch successfully applied to PID %d at 0x%lx\n", target_pid, target_vaddr);
        return 0;
    }

    if (strcmp(action, "revert") == 0) {
        if (argc < 4) {
            fprintf(stderr, "Usage: %s revert <pid> <target_vaddr_hex> <orig_bytes_hex>\n", argv[0]);
            return 1;
        }
        pid_t target_pid = atoi(argv[2]);
        uintptr_t target_vaddr = strtoull(argv[3], NULL, 16);
        const char *hex_str = argv[4];

        uint8_t orig[16];
        for (int i = 0; i < 16; i++) {
            unsigned int byte_val = 0;
            if (sscanf(hex_str + (i * 2), "%02x", &byte_val) == 1) {
                orig[i] = (uint8_t)byte_val;
            } else {
                orig[i] = 0x90; /* NOP fallback */
            }
        }

        if (ptrace(PTRACE_ATTACH, target_pid, NULL, NULL) < 0) {
            perror("ptrace attach failed");
            return 1;
        }
        int status;
        waitpid(target_pid, &status, 0);

        for (size_t i = 0; i < 16; i += 8) {
            long data = 0;
            memcpy(&data, orig + i, 8);
            ptrace(PTRACE_POKETEXT, target_pid, (void *)(target_vaddr + i), (void *)data);
        }

        ptrace(PTRACE_DETACH, target_pid, NULL, NULL);
        printf("[ulp_canary_ctl] Livepatch reverted for PID %d at 0x%lx\n", target_pid, target_vaddr);
        return 0;
    }

    print_usage(argv[0]);
    return 1;
}
