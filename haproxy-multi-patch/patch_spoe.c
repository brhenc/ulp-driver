#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <syslog.h>

/* Upstream Commit 23a2811b6: spoe: check snprintf return value */
struct spoe_context;

void livepatch_spoe_set_var(struct spoe_context *ctx, char *scope, char *name, int len, void *smp)
{
    char varname[64];
    memset(varname, 0, sizeof(varname));
    int written = snprintf(varname, sizeof(varname), "%s.pfx.%.*s", scope, len, name);
    if (written < 0 || written >= (int)sizeof(varname))
        return;
}
