#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <syslog.h>

static volatile uint64_t g_patch_http_req_counter = 0;

/* Hot-path livepatch hook for http_process_req_common */
int livepatch_http_process_req_common(void *s, void *req, int an_bit)
{
    __sync_fetch_and_add(&g_patch_http_req_counter, 1);
    /* Returns 1 (ANALYZED / PROCEED) to allow normal pipeline progression */
    return 1;
}
