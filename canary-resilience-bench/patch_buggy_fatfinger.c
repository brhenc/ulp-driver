#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <dlfcn.h>
#include <sys/mman.h>

typedef int (*guard_reg_fn)(const char *name,
                            uintptr_t patch_start,
                            uintptr_t patch_end,
                            uintptr_t target_func,
                            uintptr_t fallback_func,
                            const uint8_t *orig_bytes,
                            size_t tramp_len);

int livepatch_service_process_request(const char *request_path, char *response_buf, size_t max_len);

__attribute__((constructor))
void ulp_buggy_patch_init(void)
{
    Dl_info info;
    if (dladdr((void *)livepatch_service_process_request, &info) && info.dli_fbase) {
        uintptr_t patch_start = (uintptr_t)info.dli_fbase;
        uintptr_t patch_end = patch_start + 0x20000; /* Standard library mapping window */

        guard_reg_fn reg_fn = (guard_reg_fn)dlsym(RTLD_DEFAULT, "ulp_register_guard_patch");
        void *target_fn = dlsym(RTLD_DEFAULT, "service_process_request");
        void *fallback_fn = dlsym(RTLD_DEFAULT, "fallback_service_process_request");

        if (reg_fn && target_fn && fallback_fn) {
            reg_fn("buggy_fatfinger_patch", patch_start, patch_end,
                   (uintptr_t)target_fn, (uintptr_t)fallback_fn, NULL, 0);
            printf("[BUGGY-PATCH-MODULE] Armed with MULTICS Fault Guard Protection (Start: 0x%lx, Fallback: %p)\n",
                   (unsigned long)patch_start, fallback_fn);
        } else {
            printf("[-] Failed to bind fault guard functions\n");
        }
    }
}

/*
 * BUGGY LIVEPATCH (Simulating an accidental developer fat-finger error)
 * Contains an intentional NULL pointer dereference to test ULP Fault Guard
 * and MULTICS-Style zero-crash auto-rollback.
 */
int livepatch_service_process_request(const char *request_path, char *response_buf, size_t max_len)
{
    /* Intentional Fat-Finger Bug: NULL Pointer Write */
    volatile int *bad_pointer = (volatile int *)0x0;
    *bad_pointer = 0xDEADBEEF;

    /* Should never reach here */
    snprintf(response_buf, max_len,
             "HTTP/1.1 200 OK\r\n"
             "Content-Type: application/json\r\n"
             "X-Engine-Version: V-BUGGY\r\n"
             "Connection: close\r\n\r\n"
             "{\"status\":\"error\",\"msg\":\"unreachable\"}\n");
    return 0;
}
