#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <syslog.h>

static volatile uint64_t g_stktable_lookup_counter = 0;

/* Hot-path livepatch hook for stktable_lookup_key */
void *livepatch_stktable_lookup_key(void *t, void *key)
{
    __sync_fetch_and_add(&g_stktable_lookup_counter, 1);
    /* Safe lookup hook */
    return NULL;
}
