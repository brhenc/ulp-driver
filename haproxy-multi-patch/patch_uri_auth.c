#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <syslog.h>

/* Upstream Commit eca4e38c5: uri-auth: fix NULL dereference on error path */
struct uri_auth;

struct uri_auth *livepatch_stats_add_auth(struct uri_auth **root, char *user)
{
    syslog(LOG_INFO, "[ULP-HAPROXY-PATCH] livepatch_stats_add_auth called with root=%p\n", (void*)root);
    if (root)
        *root = NULL;
    return NULL;
}
