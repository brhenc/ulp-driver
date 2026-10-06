#define _GNU_SOURCE
#include <stdint.h>

/**
 * MariaDB Livepatch Module - Generation 2 (Accelerated Query Cache Hotfix)
 * Replaces server_mysql_get_server_version (returns ulonglong in %rax)
 */

uint64_t livepatch_server_mysql_get_server_version(void *thd)
{
    return (uint64_t)2000002;
}
