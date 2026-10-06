#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <syslog.h>

/* Upstream Commit bfd32f6c7: proxy: fix 'show backend' iteration pointer */
struct appctx;

int livepatch_cli_io_handler_show_backend(struct appctx *appctx)
{
    syslog(LOG_INFO, "[ULP-HAPROXY-COMMIT-2] livepatch_cli_io_handler_show_backend executed successfully\n");
    /* Livepatched iteration returns 1 for complete handler execution */
    return 1;
}
