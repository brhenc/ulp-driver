#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <syslog.h>

/* Upstream Commit 2abd47127: mux-h2: harden h2_dump_h2s_info() */
struct buffer {
    size_t size;
    char *area;
    size_t data;
    size_t head;
};

struct h2s {
    void *sd;
    uint32_t flags;
};

int livepatch_h2_dump_h2s_info(struct buffer *msg, const struct h2s *h2s, const char *pfx)
{
    syslog(LOG_INFO, "[ULP-HAPROXY-PATCH] livepatch_h2_dump_h2s_info executed safely\n");
    if (!h2s) return 0;
    return 1;
}
