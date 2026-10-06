#define _GNU_SOURCE
#include <stdint.h>

/**
 * PostgreSQL Livepatch Module - Generation 3 (Enterprise Lockless Hotfix)
 * Replaces pg_backend_pid() (SQL function returning Int32 Datum)
 */

int64_t livepatch_pg_backend_pid(void *fcinfo)
{
    /* Return synthetic Datum 300003 */
    return (int64_t)300003;
}
