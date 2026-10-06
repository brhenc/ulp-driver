#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <dlfcn.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <syslog.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include "ulp_uapi.h"

#define ULP_PRELOAD_RULES_CONF "/etc/ulp/preload_rules.conf"
#define ULP_OVERRIDE_TICKET "/etc/ulp/override.ticket"
#define ULP_HMAC_KEY "/etc/ulp/hmac.key"

/**
 * Constant-time memory compare to prevent timing side-channel attacks
 */
static int safe_memcmp(const void *a, const void *b, size_t len)
{
    const unsigned char *ua = (const unsigned char *)a;
    const unsigned char *ub = (const unsigned char *)b;
    unsigned char result = 0;
    for (size_t i = 0; i < len; i++) {
        result |= (ua[i] ^ ub[i]);
    }
    return (result != 0);
}

/**
 * Verify cryptographic override ticket against bitflips and forgery
 * Returns 1 if valid signed override is active, 0 otherwise (fail closed).
 */
static int verify_override_ticket(const char *exe_path)
{
    int fd = open(ULP_OVERRIDE_TICKET, O_RDONLY);
    if (fd < 0) return 0;

    struct ulp_override_ticket ticket;
    ssize_t n = read(fd, &ticket, sizeof(ticket));
    close(fd);

    if (n != sizeof(ticket)) {
        syslog(LOG_WARNING, "[ULP] Corrupted override ticket file size (%zd bytes). Failing closed.", n);
        return 0;
    }

    /* 1. Verify 256-Bit Maximum Hamming Distance Magic Guard */
    if (ticket.magic[0] != ULP_OVERRIDE_MAGIC_0 ||
        ticket.magic[1] != ULP_OVERRIDE_MAGIC_1 ||
        ticket.magic[2] != ULP_OVERRIDE_MAGIC_2 ||
        ticket.magic[3] != ULP_OVERRIDE_MAGIC_3) {
        syslog(LOG_ERR, "[ULP] CRITICAL: Override ticket 256-bit magic check failed (Bitflip/Corruption). Failing closed.");
        return 0;
    }

    /* 2. Verify Binary Path Match */
    if (strncmp(ticket.binary_path, exe_path, sizeof(ticket.binary_path)) != 0) {
        syslog(LOG_WARNING, "[ULP] Override ticket target (%s) does not match running binary (%s). Failing closed.",
               ticket.binary_path, exe_path);
        return 0;
    }

    /* 3. Verify Expiration Time Window */
    struct timeval tv;
    gettimeofday(&tv, NULL);
    uint64_t now = (uint64_t)tv.tv_sec;

    if (now > ticket.expires_at || now < ticket.issued_at) {
        syslog(LOG_WARNING, "[ULP] Override ticket expired (now=%lu, expires=%lu). Failing closed.",
               (unsigned long)now, (unsigned long)ticket.expires_at);
        return 0;
    }

    /* 4. Verify Cryptographic HMAC-SHA256 Signature */
    int key_fd = open(ULP_HMAC_KEY, O_RDONLY);
    if (key_fd < 0) {
        syslog(LOG_ERR, "[ULP] Missing /etc/ulp/hmac.key; cannot verify signature. Failing closed.");
        return 0;
    }

    unsigned char key[64];
    ssize_t key_len = read(key_fd, key, sizeof(key));
    close(key_fd);

    if (key_len < 16) {
        syslog(LOG_ERR, "[ULP] Invalid HMAC key length. Failing closed.");
        return 0;
    }

    /* Payload to authenticate: magic (32B) + binary_path (128B) + issued_at (8B) + expires_at (8B) + nonce (8B) */
    size_t payload_len = sizeof(ticket.magic) + sizeof(ticket.binary_path) + 
                         sizeof(ticket.issued_at) + sizeof(ticket.expires_at) + sizeof(ticket.nonce);
    unsigned char expected_hmac[32];
    unsigned int hmac_len = 0;

    HMAC(EVP_sha256(), key, key_len, (const unsigned char *)&ticket, payload_len, expected_hmac, &hmac_len);

    if (safe_memcmp(expected_hmac, ticket.hmac_sig, 32) != 0) {
        syslog(LOG_ALERT, "[ULP] SECURITY ALERT: Invalid HMAC signature on override ticket for %s (Tampering/Bitflip detected). Failing closed.",
               exe_path);
        return 0;
    }

    syslog(LOG_NOTICE, "[ULP] Authenticated cryptographic override verified for %s. Livepatching disabled for this execution.",
           exe_path);
    return 1;
}

/**
 * Early-Exec Constructor: Runs before main() and before sockets/threads start
 */
__attribute__((constructor(101)))
static void ulp_early_exec_init(void)
{
    char exe_path[256];
    ssize_t r = readlink("/proc/self/exe", exe_path, sizeof(exe_path) - 1);
    if (r <= 0) return;
    exe_path[r] = '\0';

    /*
     * Preload rules: one per line,
     *   <binary_path> <patch.so> <target_symbol> <patch_symbol> [func_len] [tramp_type]
     * (written by `ulp_persist add`). Kernel exec rules live in a separate file.
     */
    FILE *f = fopen(ULP_PRELOAD_RULES_CONF, "r");
    if (!f) return;

    char line[768];
    char patch_so[256] = "", target_sym[64] = "", patch_sym[64] = "";
    struct ulp_kernel_rule_req rule;
    int rule_found = 0;

    while (fgets(line, sizeof(line), f)) {
        if (line[0] == '#' || line[0] == '\n') continue;

        unsigned int flen = 0, ttype = 0;
        memset(&rule, 0, sizeof(rule));
        int parsed = sscanf(line, "%127s %255s %63s %63s %u %u",
                            rule.binary_path, patch_so, target_sym, patch_sym, &flen, &ttype);
        if (parsed >= 4 && strcmp(rule.binary_path, exe_path) == 0) {
            rule.func_len = flen;
            rule.tramp_type = ttype;
            strncpy(rule.patch_name, patch_sym, sizeof(rule.patch_name) - 1);
            strncpy(rule.func_name, target_sym, sizeof(rule.func_name) - 1);
            rule_found = 1;
            break;
        }
    }
    fclose(f);

    if (!rule_found) return;

    /* Verify if an emergency cryptographic override ticket is present */
    if (verify_override_ticket(exe_path)) {
        return; /* Operator authorized bypass */
    }

    /* Resolve the target symbol in the running process */
    void *target_sym_addr = dlsym(RTLD_DEFAULT, target_sym);
    if (!target_sym_addr) {
        return;
    }

    /* Load the patch library and resolve the replacement symbol in it */
    void *patch_handle = dlopen(patch_so, RTLD_NOW | RTLD_GLOBAL);
    if (patch_handle) {
        void *addr = dlsym(patch_handle, patch_sym);
        if (addr)
            rule.patch_vaddr = (uint64_t)(uintptr_t)addr;
    }

    if (rule.patch_vaddr == 0) {
        syslog(LOG_ERR, "[ULP] Early-exec rejected: patch_vaddr is 0 (NULL jump prevented) for symbol %s", rule.func_name);
        return;
    }

    /* Open /dev/ulp and Apply Livepatch */
    int dev_fd = open("/dev/ulp", O_RDWR);
    if (dev_fd < 0) {
        return;
    }

    struct ulp_patch_req req;
    memset(&req, 0, sizeof(req));
    req.target_pid = (uint32_t)getpid();
    strncpy(req.patch_name, rule.patch_name, sizeof(req.patch_name) - 1);
    strncpy(req.func_name, rule.func_name, sizeof(req.func_name) - 1);
    req.target_vaddr = (uint64_t)(uintptr_t)target_sym_addr;
    req.patch_vaddr = rule.patch_vaddr;
    req.func_len = rule.func_len;
    req.tramp_type = rule.tramp_type;

    if (ioctl(dev_fd, ULP_IOC_APPLY_PATCH, &req) < 0) {
        syslog(LOG_ERR, "[ULP] Early-exec ioctl failed for PID %d (%s @ %p -> 0x%llx)",
               getpid(), rule.func_name, target_sym_addr, (unsigned long long)rule.patch_vaddr);
    } else {
        syslog(LOG_INFO, "[ULP] SUCCESS: Persistent livepatch applied to %s (PID %d) at symbol %s [%p -> 0x%llx] before main()",
               exe_path, getpid(), rule.func_name, target_sym_addr, (unsigned long long)rule.patch_vaddr);
    }

    close(dev_fd);
}
