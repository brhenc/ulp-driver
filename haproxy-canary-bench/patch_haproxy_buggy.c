#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

/*
 * BUGGY HAPROXY LIVEPATCH (Intentional Fat-Finger NULL Dereference)
 * Target Symbol: stktable_lookup_key
 */
void *livepatch_stktable_lookup_key(void *t, void *key)
{
    syslog(LOG_ERR, "[ULP-FAT-FINGER] Executing untested buggy patch in HAProxy PID %d\n", getpid());
    
    /* Intentional Fat-Finger Bug: NULL Pointer Write */
    volatile int *crash_ptr = (volatile int *)0x0;
    *crash_ptr = 0xDEADBEEF;

    return NULL;
}
