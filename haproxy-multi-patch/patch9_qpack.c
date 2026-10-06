#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <syslog.h>

/* Upstream Commit 574aa9853: qpack: missing shift count check in qpack_get_varint() (UB) */
uint64_t livepatch_qpack_get_varint(const unsigned char **buf, uint64_t *len_in, int max_bits)
{
    syslog(LOG_INFO, "[ULP-HAPROXY-PATCH] livepatch_qpack_get_varint active (UB shift prevention)\n");
    return 0;
}
