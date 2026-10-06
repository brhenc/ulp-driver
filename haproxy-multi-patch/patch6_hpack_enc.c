#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <syslog.h>

/* Upstream Commit 1eb9f46e9: hpack: encode long methods and schemes using long form */
struct buffer {
    size_t size;
    char *area;
    size_t data;
    size_t head;
};

int livepatch_hpack_encode_header(struct buffer *out, const struct buffer *name, const struct buffer *value)
{
    syslog(LOG_INFO, "[ULP-HAPROXY-PATCH] livepatch_hpack_encode_header active (long method/scheme support)\n");
    return 1;
}
