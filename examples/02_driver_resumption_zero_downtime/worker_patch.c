/*
 * ulp-driver: ULP Example 2 - Worker Livepatch Payload
 *
 * Replaces the work unit execution engine with an accelerated implementation.
 */

#include <stdio.h>

/*
 * REPLACEMENT FUNCTION: livepatch_process_work_unit
 */
__attribute__((noinline, aligned(16)))
const char *livepatch_process_work_unit(int unit_id)
{
    static char buf[256];
    snprintf(buf, sizeof(buf), "RESULT: unit=%d | engine=v2_ACCELERATED | status=HOTPATCHED\n", unit_id);
    return buf;
}
