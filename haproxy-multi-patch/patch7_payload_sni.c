#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <syslog.h>

/* Upstream Commit 489163624: payload: smp_client_hello_parse cleanup */
int livepatch_smp_client_hello_parse(const char *buf, size_t len, void *res)
{
    syslog(LOG_INFO, "[ULP-HAPROXY-PATCH] livepatch_smp_client_hello_parse active\n");
    if (!buf || len < 5) return 0;
    return 1;
}
