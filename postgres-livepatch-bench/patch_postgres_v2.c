#define _GNU_SOURCE
#include <stdint.h>

/**
 * PostgreSQL Livepatch Module - Generation 2 (Accelerated Query Cache Hotfix)
 * Replaces pg_backend_pid() (SQL function returning Int32 Datum)
 */

int64_t livepatch_pg_backend_pid(void *fcinfo)
{
    /* Return synthetic Datum 200002 */
    return (int64_t)200002;
}
