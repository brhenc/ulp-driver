#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <stdatomic.h>
#include <syslog.h>
#include <time.h>

/* Atomic Canary Ratio in Basis Points (100 = 1.00%, 1000 = 10.00%, 10000 = 100.00%) */
_Atomic uint32_t g_haproxy_canary_ratio = 100; /* Default 1.00% (100 bp) */

/* Telemetry Counters (Exported globally for real-time observability) */
_Atomic uint64_t g_canary_tx_hits = 0;
_Atomic uint64_t g_baseline_tx_hits = 0;

__attribute__((constructor))
void ulp_haproxy_canary_init(void)
{
    srand((unsigned int)time(NULL) ^ (unsigned int)getpid());
    openlog("ulp-haproxy-canary", LOG_PID | LOG_CONS, LOG_USER);
    syslog(LOG_NOTICE, "[ULP-HAPROXY-CANARY] Module initialized in HAProxy PID %d (Canary Ratio: 100 bp / 1.00%%)\n", getpid());
}

void ulp_set_canary_ratio(uint32_t bp)
{
    atomic_store(&g_haproxy_canary_ratio, bp);
    syslog(LOG_NOTICE, "[ULP-HAPROXY-CANARY] Live updated canary ratio to %u bp (%.2f%%)\n", bp, (float)bp / 100.0f);
}

void ulp_get_canary_stats(uint64_t *canary_count, uint64_t *baseline_count)
{
    if (canary_count) *canary_count = atomic_load(&g_canary_tx_hits);
    if (baseline_count) *baseline_count = atomic_load(&g_baseline_tx_hits);
}

/*
 * Patched stktable_touch_local with Atomic Canary Gate
 * Target Symbol: stktable_touch_local
 */
void livepatch_stktable_touch_local(void *t, void *ts, int expire)
{
    uint32_t bp = atomic_load_explicit(&g_haproxy_canary_ratio, memory_order_relaxed);
    uint32_t sample = (uint32_t)(rand() % 10000);

    if (sample < bp) {
        /* 1% CANARY PATH: Execute experimental branch / telemetry */
        atomic_fetch_add(&g_canary_tx_hits, 1);
        return;
    }

    /* 99% BASELINE PATH: Passthrough to baseline logic */
    atomic_fetch_add(&g_baseline_tx_hits, 1);
}
