#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include "ulp_uapi.h"
#include "ulp_buildid.h"

#define ULP_CONFIG_DIR "/etc/ulp"
#define ULP_RULES_CONF "/etc/ulp/persistent_rules.conf"
#define ULP_OVERRIDE_TICKET "/etc/ulp/override.ticket"
#define ULP_HMAC_KEY "/etc/ulp/hmac.key"

static void ensure_config_dir(void)
{
    struct stat st;
    if (stat(ULP_CONFIG_DIR, &st) != 0) {
        mkdir(ULP_CONFIG_DIR, 0700);
    }
}

static int generate_key(void)
{
    ensure_config_dir();
    unsigned char key[32];
    if (RAND_bytes(key, sizeof(key)) != 1) {
        /* Fallback to /dev/urandom */
        int rnd_fd = open("/dev/urandom", O_RDONLY);
        if (rnd_fd < 0 || read(rnd_fd, key, sizeof(key)) != sizeof(key)) {
            perror("[-] Failed to read randomness for HMAC key");
            if (rnd_fd >= 0) close(rnd_fd);
            return 1;
        }
        close(rnd_fd);
    }

    int fd = open(ULP_HMAC_KEY, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) {
        perror("[-] Failed to open /etc/ulp/hmac.key");
        return 1;
    }
    write(fd, key, sizeof(key));
    close(fd);

    printf("[+] Generated 256-bit cryptographic HMAC key at %s (Mode 0600)\n", ULP_HMAC_KEY);
    return 0;
}

static int add_rule(const char *bin_path, const char *patch_so,
                    const char *target_sym, const char *patch_sym,
                    uint32_t func_len, uint32_t tramp_type)
{
    ensure_config_dir();
    FILE *f = fopen(ULP_RULES_CONF, "a");
    if (!f) {
        perror("[-] Failed to open persistent_rules.conf");
        return 1;
    }

    fprintf(f, "%s %s %s %s %u %u\n",
            bin_path, patch_so, target_sym, patch_sym, func_len, tramp_type);
    fclose(f);

    printf("[+] Registered persistent livepatch rule for %s -> %s [%s -> %s]\n",
           bin_path, patch_so, target_sym, patch_sym);
    return 0;
}

static int load_rules(void)
{
    FILE *f = fopen(ULP_RULES_CONF, "r");
    if (!f) {
        printf("[!] No persistent rules found at %s\n", ULP_RULES_CONF);
        return 0;
    }

    int dev_fd = open("/dev/ulp", O_RDWR);
    if (dev_fd < 0) {
        perror("[-] Failed to open /dev/ulp");
        fclose(f);
        return 1;
    }

    char line[512];
    int loaded = 0;
    while (fgets(line, sizeof(line), f)) {
        if (line[0] == '#' || line[0] == '\n') continue;
        struct ulp_kernel_rule_req rreq;
        memset(&rreq, 0, sizeof(rreq));

        char target_off_str[64] = "0";
        char patch_vaddr_str[64] = "0";
        char build_id_str[64] = "";
        rreq.func_len = 16;
        /* Support both colon-delimited and whitespace-delimited configs */
        for (char *c = line; *c; c++) {
            if (*c == ':') *c = ' ';
        }

        int parsed = sscanf(line, "%127s %63s %63s %63s %63s %u %u %hhu %63s",
                            rreq.binary_path, rreq.patch_name, rreq.func_name,
                            target_off_str, patch_vaddr_str,
                            &rreq.func_len, &rreq.match_uid, &rreq.global_scope, build_id_str);

        /*
         * Optional 9th field "build_id=<hex>" (from `ulp_ctl build-id <binary>`), recorded when
         * the rule was written. It is deliberately not computed here: at boot the binary may
         * already have been replaced, and the rule must then be skipped, not re-targeted.
         */
        if (parsed >= 9) {
            int idlen = -1;

            if (strncmp(build_id_str, "build_id=", 9) == 0)
                idlen = ulp_build_id_from_hex(build_id_str + 9, rreq.build_id, sizeof(rreq.build_id));
            if (idlen < 0) {
                fprintf(stderr, "[-] Invalid build_id field for %s: %s\n", rreq.binary_path, build_id_str);
                continue;
            }
            rreq.build_id_len = (uint8_t)idlen;
        }

        if (parsed >= 3) {
            rreq.target_offset = strtoull(target_off_str, NULL, 16);
            rreq.patch_vaddr = strtoull(patch_vaddr_str, NULL, 16);

            if (rreq.patch_vaddr == 0) {
                rreq.tramp_type = ULP_TRAMP_ABS16;
                rreq.patch_bytes[0] = 0xF3; rreq.patch_bytes[1] = 0x0F; rreq.patch_bytes[2] = 0x1E; rreq.patch_bytes[3] = 0xFA; /* endbr64 */
                rreq.patch_bytes[4] = 0x31; rreq.patch_bytes[5] = 0xC0; /* xor %eax, %eax */
                rreq.patch_bytes[6] = 0xC3; /* ret */
                memset(&rreq.patch_bytes[7], 0x90, 9);
            } else if (rreq.func_len < 16) {
                rreq.tramp_type = ULP_TRAMP_REL5;
                rreq.patch_bytes[0] = 0xE9;
            } else {
                rreq.tramp_type = ULP_TRAMP_ABS16;
                rreq.patch_bytes[0] = 0xF3; rreq.patch_bytes[1] = 0x0F; rreq.patch_bytes[2] = 0x1E; rreq.patch_bytes[3] = 0xFA;
                rreq.patch_bytes[4] = 0x48; rreq.patch_bytes[5] = 0xB8;
                memcpy(&rreq.patch_bytes[6], &rreq.patch_vaddr, 8);
                rreq.patch_bytes[14] = 0xFF; rreq.patch_bytes[15] = 0xE0;
            }

            if (ioctl(dev_fd, ULP_IOC_ADD_RULE, &rreq) == 0) {
                printf("[+] Loaded persistent rule into kernel: %s -> 0x%llx [%s::%s]\n",
                       rreq.binary_path, (unsigned long long)rreq.target_offset, rreq.patch_name, rreq.func_name);
                loaded++;
            } else {
                perror("[-] ioctl(ULP_IOC_ADD_RULE) failed");
            }
        }
    }

    fclose(f);
    close(dev_fd);
    printf("[+] Total in-kernel persistent rules activated on boot: %d\n", loaded);
    return 0;
}

static int list_rules(void)
{
    FILE *f = fopen(ULP_RULES_CONF, "r");
    if (!f) {
        printf("[!] No persistent rules registered yet (%s not found)\n", ULP_RULES_CONF);
        return 0;
    }

    char line[512];
    printf("\n=== ACTIVE PERSISTENT LIVEPATCH RULES (%s) ===\n", ULP_RULES_CONF);
    printf("%-30s %-20s %-20s %-16s %-16s %-6s\n",
           "BINARY PATH", "PATCH NAME", "FUNCTION", "TARGET OFFSET", "PATCH VADDR", "LEN");
    printf("--------------------------------------------------------------------------------------------------------------------\n");
    while (fgets(line, sizeof(line), f)) {
        if (line[0] == '#' || line[0] == '\n') continue;
        char bin[128], pch[64], fn[64], off[64], vaddr[64];
        uint32_t len = 0, uid = 0, glob = 0;
        if (sscanf(line, "%127s %63s %63s %63s %63s %u %u %u", bin, pch, fn, off, vaddr, &len, &uid, &glob) >= 3) {
            printf("%-30s %-20s %-20s %-16s %-16s %-6u\n", bin, pch, fn, off, vaddr, len);
        }
    }
    fclose(f);
    printf("--------------------------------------------------------------------------------------------------------------------\n\n");
    return 0;
}

static int create_override_ticket(const char *bin_path, uint64_t ttl_seconds)
{
    ensure_config_dir();
    if (access(ULP_HMAC_KEY, R_OK) != 0) {
        printf("[*] Generating missing HMAC secret key...\n");
        generate_key();
    }

    int key_fd = open(ULP_HMAC_KEY, O_RDONLY);
    if (key_fd < 0) {
        perror("[-] Failed to open /etc/ulp/hmac.key");
        return 1;
    }

    unsigned char key[64];
    ssize_t key_len = read(key_fd, key, sizeof(key));
    close(key_fd);

    struct ulp_override_ticket ticket;
    memset(&ticket, 0, sizeof(ticket));

    /* Set 256-Bit Maximum Hamming Distance Magic Constants */
    ticket.magic[0] = ULP_OVERRIDE_MAGIC_0;
    ticket.magic[1] = ULP_OVERRIDE_MAGIC_1;
    ticket.magic[2] = ULP_OVERRIDE_MAGIC_2;
    ticket.magic[3] = ULP_OVERRIDE_MAGIC_3;

    strncpy(ticket.binary_path, bin_path, sizeof(ticket.binary_path) - 1);

    struct timeval tv;
    gettimeofday(&tv, NULL);
    ticket.issued_at = (uint64_t)tv.tv_sec;
    ticket.expires_at = ticket.issued_at + ttl_seconds;

    /* Random Nonce */
    int rnd_fd = open("/dev/urandom", O_RDONLY);
    if (rnd_fd >= 0) {
        read(rnd_fd, &ticket.nonce, sizeof(ticket.nonce));
        close(rnd_fd);
    }

    /* Compute HMAC-SHA256 over all fields */
    size_t payload_len = sizeof(ticket.magic) + sizeof(ticket.binary_path) + 
                         sizeof(ticket.issued_at) + sizeof(ticket.expires_at) + sizeof(ticket.nonce);
    unsigned int hmac_len = 0;

    HMAC(EVP_sha256(), key, key_len, (const unsigned char *)&ticket, payload_len, ticket.hmac_sig, &hmac_len);

    int fd = open(ULP_OVERRIDE_TICKET, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) {
        perror("[-] Failed to write /etc/ulp/override.ticket");
        return 1;
    }
    write(fd, &ticket, sizeof(ticket));
    close(fd);

    printf("[+] Successfully generated signed cryptographic override ticket for '%s'\n", bin_path);
    printf("    Issued At:  %lu\n", (unsigned long)ticket.issued_at);
    printf("    Expires At: %lu (Valid for %lu seconds)\n", (unsigned long)ticket.expires_at, (unsigned long)ttl_seconds);
    printf("    Ticket Path: %s (Mode 0600)\n", ULP_OVERRIDE_TICKET);
    return 0;
}

static int clear_override_ticket(void)
{
    if (unlink(ULP_OVERRIDE_TICKET) == 0) {
        printf("[+] Cryptographic override ticket removed. Livepatching is fully active.\n");
    } else {
        printf("[*] No active override ticket found.\n");
    }
    return 0;
}

static void print_usage(const char *prog)
{
    printf("Usage: %s <command> [args...]\n", prog);
    printf("Commands:\n");
    printf("  add <bin_path> <patch_so> <target_sym> <patch_sym> [func_len] [tramp_type]\n");
    printf("      Register a persistent auto-livepatch rule for an executable\n");
    printf("  list\n");
    printf("      List all registered persistent livepatch rules\n");
    printf("  generate-key\n");
    printf("      Generate root HMAC-SHA256 signing key in /etc/ulp/hmac.key\n");
    printf("  create-override <bin_path> [ttl_seconds]\n");
    printf("      Generate a tamper-proof, cryptographic signed override ticket\n");
    printf("  clear-override\n");
    printf("      Delete active override ticket and re-enable livepatching\n");
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }

    const char *cmd = argv[1];
    if (strcmp(cmd, "add") == 0) {
        if (argc < 6) {
            fprintf(stderr, "Error: 'add' requires <bin_path> <patch_so> <target_sym> <patch_sym> [func_len]\n");
            return 1;
        }
        uint32_t func_len = (argc >= 7) ? (uint32_t)atoi(argv[6]) : 0;
        uint32_t tramp_type = (argc >= 8) ? (uint32_t)atoi(argv[7]) : 0;
        return add_rule(argv[2], argv[3], argv[4], argv[5], func_len, tramp_type);
    } else if (strcmp(cmd, "load-rules") == 0) {
        return load_rules();
    } else if (strcmp(cmd, "list") == 0) {
        return list_rules();
    } else if (strcmp(cmd, "generate-key") == 0) {
        return generate_key();
    } else if (strcmp(cmd, "create-override") == 0) {
        if (argc < 3) {
            fprintf(stderr, "Error: 'create-override' requires <bin_path> [ttl_seconds]\n");
            return 1;
        }
        uint64_t ttl = (argc >= 4) ? (uint64_t)strtoull(argv[3], NULL, 10) : 300;
        return create_override_ticket(argv[2], ttl);
    } else if (strcmp(cmd, "clear-override") == 0) {
        return clear_override_ticket();
    } else {
        fprintf(stderr, "Unknown command: %s\n", cmd);
        print_usage(argv[0]);
        return 1;
    }
}
