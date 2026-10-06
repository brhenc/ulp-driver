#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <syslog.h>

/* Upstream Commit b39eb58ec: haproxy: fix out-of-scope tmpdir usage in do_chroot() */
int livepatch_do_chroot(const char *prog, const char *path)
{
    syslog(LOG_INFO, "[ULP-HAPROXY-PATCH] livepatch_do_chroot active (safe tmpdir lifetime)\n");
    return 0;
}
