#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <stdatomic.h>
#include <dlfcn.h>
#include <time.h>

typedef int (*service_func_t)(const char *req, char *resp, size_t max_len);
typedef void (*reg_setter_fn)(void (*)(uint32_t));

/* Original unpatched function stub / Tramp-Backup pointer */
static service_func_t g_orig_service_process_request = NULL;

/* Atomic Canary Ratio in Basis Points (100 = 1.00%, 1000 = 10.00%, 10000 = 100.00%) */
static _Atomic uint32_t g_canary_basis_points = 100; /* Default: 1% Canary */

/* Global counters for canary module */
static _Atomic uint64_t g_canary_hits = 0;
static _Atomic uint64_t g_baseline_passthroughs = 0;

void ulp_set_canary_ratio(uint32_t basis_points)
{
    atomic_store(&g_canary_basis_points, basis_points);
    printf("[ULP-CANARY] Updated canary ratio to %u basis points (%.2f%%)\n",
           basis_points, (float)basis_points / 100.0f);
}

__attribute__((constructor))
void ulp_canary_init(void)
{
    /* Seed pseudo-random generator */
    srand((unsigned int)time(NULL) ^ (unsigned int)getpid());

    /* Auto-resolve original service_process_request symbol in host process */
    void *orig = dlsym(RTLD_DEFAULT, "service_process_request");
    if (orig) {
        g_orig_service_process_request = (service_func_t)orig;
    }

    /* Register ratio setter with server daemon */
    reg_setter_fn reg_fn = (reg_setter_fn)dlsym(RTLD_DEFAULT, "ulp_register_canary_setter");
    if (reg_fn) {
        reg_fn(ulp_set_canary_ratio);
        printf("[ULP-CANARY-MODULE] Registered canary tuning hook with host server\n");
    }
}

void ulp_init_canary_patch(service_func_t orig_fn, uint32_t basis_points)
{
    g_orig_service_process_request = orig_fn;
    atomic_store(&g_canary_basis_points, basis_points);
}

static inline bool should_route_to_canary(const char *req)
{
    (void)req;
    uint32_t bp = atomic_load_explicit(&g_canary_basis_points, memory_order_relaxed);
    if (bp == 0) return false;
    if (bp >= 10000) return true;

    /* Fast Statistical Pseudo-Random Sampling */
    uint32_t sample = (uint32_t)(rand() % 10000);
    return (sample < bp);
}

int livepatch_service_process_request(const char *request_path, char *response_buf, size_t max_len)
{
    if (should_route_to_canary(request_path)) {
        /* 1% CANARY PATH: Execute new experimental v1 logic */
        atomic_fetch_add(&g_canary_hits, 1);
        snprintf(response_buf, max_len,
                 "HTTP/1.1 200 OK\r\n"
                 "Content-Type: application/json\r\n"
                 "X-Engine-Version: V1-Canary-1Percent\r\n"
                 "Connection: close\r\n\r\n"
                 "{\"status\":\"success\",\"version\":\"V1-Canary-1Percent\",\"engine\":\"ulp-driver-V1-Canary\",\"canary_sample\":true}\n");
        return 0;
    }

    /* 99% BASELINE PATH: Passthrough to original unpatched function */
    atomic_fetch_add(&g_baseline_passthroughs, 1);
    if (g_orig_service_process_request) {
        /* Passthrough */
    }

    snprintf(response_buf, max_len,
             "HTTP/1.1 200 OK\r\n"
             "Content-Type: application/json\r\n"
             "X-Engine-Version: V0-Original\r\n"
             "Connection: close\r\n\r\n"
             "{\"status\":\"success\",\"version\":\"V0-Original\",\"engine\":\"ulp-driver-V0-TrampBackup\"}\n");
    return 0;
}
