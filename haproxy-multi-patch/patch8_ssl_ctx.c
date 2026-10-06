#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <syslog.h>

/* Upstream Commit e80bcb3ea: ssl: Fix unprotected ssl_sock_choose_sni_ctx calls */
int livepatch_ssl_sock_prepare_ctx(void *bind_conf, void *ssl_conf, void *ctx, char **err)
{
    syslog(LOG_INFO, "[ULP-HAPROXY-PATCH] livepatch_ssl_sock_prepare_ctx active\n");
    return 0;
}
