#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>

/**
 * PostgreSQL Livepatch Module:
 * Replaces pg_backend_pid() (SQL function returning Int32 Datum)
 * Datum on x86_64 is passed/returned as a 64-bit scalar in %rax.
 */

int64_t livepatch_pg_backend_pid(void *fcinfo)
{
    /* Return synthetic PID 999999 as Datum */
    return (int64_t)999999;
}
