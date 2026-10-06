#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <syslog.h>

struct appctx;

/* Upstream Commit bfd32f6c7: proxy: fix 'show backend' */
int livepatch_cli_io_handler_show_backend(struct appctx *appctx)
{
    syslog(LOG_INFO, "[ULP-HAPROXY-PATCH] livepatch_cli_io_handler_show_backend active\n");
    return 1;
}
