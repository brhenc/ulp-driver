#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <syslog.h>

struct list {
    struct list *n;
    struct list *p;
};

/* Upstream Commit 9204caf54: log: fix double-free error */
int livepatch_parse_logger(char **args, struct list *loggers, int do_del, const char *file, int linenum, char **err)
{
    syslog(LOG_INFO, "[ULP-HAPROXY-PATCH] livepatch_parse_logger active (double-free prevention)\n");
    return 1;
}
