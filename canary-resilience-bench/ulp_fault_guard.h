#ifndef ULP_FAULT_GUARD_H
#define ULP_FAULT_GUARD_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <setjmp.h>

#ifdef __cplusplus
extern "C" {
#endif

#define ULP_GUARD_MAX_PATCHES 32
#define ULP_GUARD_MAX_NAME_LEN 64
#define ULP_MAX_TRAMP_BYTES 32

typedef struct {
    char name[ULP_GUARD_MAX_NAME_LEN];
    uintptr_t patch_start;
    uintptr_t patch_end;
    uintptr_t target_func;
    uintptr_t fallback_func;
    uint8_t orig_bytes[ULP_MAX_TRAMP_BYTES];
    size_t tramp_len;
    volatile int quarantined;
    volatile uint64_t fault_count;
    bool active;
} ulp_patch_guard_entry_t;

/* Thread-local recovery checkpoint context */
typedef struct {
    sigjmp_buf env;
    volatile bool active;
} ulp_thread_checkpoint_t;

extern __thread ulp_thread_checkpoint_t g_ulp_thread_checkpoint;

/* Initialize alternate signal stack and fault interception handlers */
int ulp_init_fault_guard(void);

/* Register a livepatch code region with its target and fallback routes */
int ulp_register_guard_patch(const char *name,
                             uintptr_t patch_start,
                             uintptr_t patch_end,
                             uintptr_t target_func,
                             uintptr_t fallback_func,
                             const uint8_t *orig_bytes,
                             size_t tramp_len);

/* Check if a patch has been auto-quarantined due to a trapped fault */
bool ulp_is_patch_quarantined(const char *name);

/* Mark patch as quarantined manually */
void ulp_quarantine_patch(const char *name);

/* Global Telemetry Metrics */
uint64_t ulp_get_total_faults_intercepted(void);
uint64_t ulp_get_total_crashes_prevented(void);
void ulp_print_guard_status(void);

/* Macro for wrapping livepatchable business calls in a MULTICS-style resilient frame */
#define ULP_GUARDED_CALL(call_expr, fallback_expr) \
    do { \
        g_ulp_thread_checkpoint.active = true; \
        if (sigsetjmp(g_ulp_thread_checkpoint.env, 1) == 0) { \
            call_expr; \
        } else { \
            fallback_expr; \
        } \
        g_ulp_thread_checkpoint.active = false; \
    } while (0)

#ifdef __cplusplus
}
#endif

#endif /* ULP_FAULT_GUARD_H */
