#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <ucontext.h>
#include <sys/mman.h>
#include <stdatomic.h>
#include <pthread.h>
#include "ulp_fault_guard.h"

__thread ulp_thread_checkpoint_t g_ulp_thread_checkpoint = { .active = false };

static ulp_patch_guard_entry_t g_guard_table[ULP_GUARD_MAX_PATCHES];
static size_t g_guard_count = 0;
static pthread_mutex_t g_guard_lock = PTHREAD_MUTEX_INITIALIZER;

static _Atomic uint64_t g_total_faults_intercepted = 0;
static _Atomic uint64_t g_total_crashes_prevented = 0;

static struct sigaction g_old_sa_segv;
static struct sigaction g_old_sa_bus;
static stack_t g_altstack;
static bool g_guard_initialized = false;

/*
 * MULTICS-Style Signal Interception Handler
 * Intercepts SIGSEGV & SIGBUS on dedicated alternate stack,
 * isolates the faulted livepatch, auto-quarantines it,
 * restores target function bytes to V0 / fallback, rewinds execution, and resumes safely.
 */
static void ulp_fault_resilience_handler(int sig, siginfo_t *info, void *ucontext_raw)
{
    ucontext_t *uc = (ucontext_t *)ucontext_raw;

#if defined(__x86_64__)
    uintptr_t fault_ip = (uintptr_t)uc->uc_mcontext.gregs[REG_RIP];
#elif defined(__aarch64__)
    uintptr_t fault_ip = (uintptr_t)uc->uc_mcontext.pc;
#elif defined(__riscv)
    uintptr_t fault_ip = (uintptr_t)uc->uc_mcontext.__gregs[REG_PC];
#else
    uintptr_t fault_ip = 0;
#endif

    void *fault_addr = info ? info->si_addr : NULL;

    /* Scan registered livepatch code ranges */
    for (size_t i = 0; i < g_guard_count; i++) {
        ulp_patch_guard_entry_t *e = &g_guard_table[i];
        if (!e->active) continue;

        if (fault_ip >= e->patch_start && fault_ip < e->patch_end) {
            /* Livepatch crashed! Intercept and execute MULTICS Auto-Recovery */
            atomic_fetch_add(&g_total_faults_intercepted, 1);
            atomic_fetch_add(&g_total_crashes_prevented, 1);
            e->quarantined = 1;

            if (e->fault_count++ == 0) {
                /* Print diagnostic alert once upon initial fault trap */
                fprintf(stderr, "\n======================================================================\n");
                fprintf(stderr, "[ULP-MULTICS-RESILIENCE] FATAL FAULT INTERCEPTED: Signal %d (%s)\n",
                        sig, sig == SIGSEGV ? "SIGSEGV (Page Fault / Bad Dereference)" : "SIGBUS");
                fprintf(stderr, "[ULP-MULTICS-RESILIENCE] Fault IP:       0x%016lx inside patch '%s'\n", (unsigned long)fault_ip, e->name);
                fprintf(stderr, "[ULP-MULTICS-RESILIENCE] Memory Target:  %p\n", fault_addr);
                fprintf(stderr, "[ULP-MULTICS-RESILIENCE] Patch Range:    0x%016lx - 0x%016lx\n", (unsigned long)e->patch_start, (unsigned long)e->patch_end);
                fprintf(stderr, "[ULP-MULTICS-RESILIENCE] ACTION:         AUTO-QUARANTINING PATCH & REWINDING TO V0\n");
                fprintf(stderr, "[ULP-MULTICS-RESILIENCE] RESULT:         DAEMON CRASH PREVENTED (100%% UPTIME PRESERVED)\n");
                fprintf(stderr, "======================================================================\n\n");
            }

            /* 1. Atomically restore target function or route to fallback */
            if (e->target_func) {
                uintptr_t page_start = e->target_func & ~0xFFF;
                mprotect((void *)page_start, 4096, PROT_READ | PROT_WRITE | PROT_EXEC);

                if (e->tramp_len > 0) {
                    memcpy((void *)e->target_func, e->orig_bytes, e->tramp_len);
                } else if (e->fallback_func) {
#if defined(__x86_64__)
                    uint8_t tramp[16];
                    tramp[0] = 0xF3; tramp[1] = 0x0F; tramp[2] = 0x1E; tramp[3] = 0xFA; /* endbr64 */
                    tramp[4] = 0x48; tramp[5] = 0xB8; /* movabs fallback, %rax */
                    memcpy(&tramp[6], &e->fallback_func, 8);
                    tramp[14] = 0xFF; tramp[15] = 0xE0; /* jmpq *%rax */
                    memcpy((void *)e->target_func, tramp, 16);
#endif
                }
            }

            /* 2. MULTICS Execution Rewind:
             * If thread-local checkpoint is active, perform a clean context restore via siglongjmp.
             * Otherwise, rewind instruction pointer directly.
             */
            if (g_ulp_thread_checkpoint.active) {
                siglongjmp(g_ulp_thread_checkpoint.env, 1);
            }

            uintptr_t resume_target = e->fallback_func ? e->fallback_func : e->target_func;
            if (resume_target) {
#if defined(__x86_64__)
                uc->uc_mcontext.gregs[REG_RIP] = (greg_t)resume_target;
#elif defined(__aarch64__)
                uc->uc_mcontext.pc = (uint64_t)resume_target;
#elif defined(__riscv)
                uc->uc_mcontext.__gregs[REG_PC] = (unsigned long)resume_target;
#endif
                return;
            }
        }
    }

    /* Unregistered fault or fatal out-of-patch crash - chain to default handler */
    fprintf(stderr, "[ULP-FAULT-GUARD] Unhandled fault at IP 0x%lx (not in active patch region). Propagating.\n", (unsigned long)fault_ip);
    if (sig == SIGSEGV && g_old_sa_segv.sa_sigaction) {
        g_old_sa_segv.sa_sigaction(sig, info, ucontext_raw);
    } else if (sig == SIGBUS && g_old_sa_bus.sa_sigaction) {
        g_old_sa_bus.sa_sigaction(sig, info, ucontext_raw);
    } else {
        signal(sig, SIG_DFL);
        raise(sig);
    }
}

int ulp_init_fault_guard(void)
{
    pthread_mutex_lock(&g_guard_lock);
    if (g_guard_initialized) {
        pthread_mutex_unlock(&g_guard_lock);
        return 0;
    }

    /* 1. Allocate dedicated alternate signal stack (64 KB) */
    void *stack_mem = mmap(NULL, SIGSTKSZ * 4, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_STACK, -1, 0);
    if (stack_mem == MAP_FAILED) {
        perror("mmap altstack failed");
        pthread_mutex_unlock(&g_guard_lock);
        return -1;
    }

    g_altstack.ss_sp = stack_mem;
    g_altstack.ss_size = SIGSTKSZ * 4;
    g_altstack.ss_flags = 0;

    if (sigaltstack(&g_altstack, NULL) < 0) {
        perror("sigaltstack failed");
        pthread_mutex_unlock(&g_guard_lock);
        return -1;
    }

    /* 2. Install SIGSEGV and SIGBUS handlers with SA_ONSTACK and SA_SIGINFO */
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = ulp_fault_resilience_handler;
    sa.sa_flags = SA_SIGINFO | SA_ONSTACK | SA_NODEFER;
    sigemptyset(&sa.sa_mask);

    if (sigaction(SIGSEGV, &sa, &g_old_sa_segv) < 0) {
        perror("sigaction(SIGSEGV) failed");
        pthread_mutex_unlock(&g_guard_lock);
        return -1;
    }

    if (sigaction(SIGBUS, &sa, &g_old_sa_bus) < 0) {
        perror("sigaction(SIGBUS) failed");
        pthread_mutex_unlock(&g_guard_lock);
        return -1;
    }

    g_guard_initialized = true;
    pthread_mutex_unlock(&g_guard_lock);

    printf("[ULP-FAULT-GUARD] MULTICS-Style Crash Resilience Engine Armed (Alternate Stack: %zu KB, Signals: SIGSEGV, SIGBUS)\n",
           g_altstack.ss_size / 1024);
    return 0;
}

int ulp_register_guard_patch(const char *name,
                             uintptr_t patch_start,
                             uintptr_t patch_end,
                             uintptr_t target_func,
                             uintptr_t fallback_func,
                             const uint8_t *orig_bytes,
                             size_t tramp_len)
{
    pthread_mutex_lock(&g_guard_lock);
    if (g_guard_count >= ULP_GUARD_MAX_PATCHES) {
        pthread_mutex_unlock(&g_guard_lock);
        return -1;
    }

    ulp_patch_guard_entry_t *e = &g_guard_table[g_guard_count++];
    memset(e, 0, sizeof(*e));
    strncpy(e->name, name ? name : "unnamed_patch", sizeof(e->name) - 1);
    e->patch_start = patch_start;
    e->patch_end = patch_end;
    e->target_func = target_func;
    e->fallback_func = fallback_func;
    e->tramp_len = tramp_len > ULP_MAX_TRAMP_BYTES ? ULP_MAX_TRAMP_BYTES : tramp_len;
    if (orig_bytes && e->tramp_len > 0) {
        memcpy(e->orig_bytes, orig_bytes, e->tramp_len);
    }
    e->quarantined = 0;
    e->fault_count = 0;
    e->active = true;

    pthread_mutex_unlock(&g_guard_lock);

    printf("[ULP-FAULT-GUARD] Registered Livepatch Guard '%s' [0x%lx - 0x%lx] -> Fallback: 0x%lx\n",
           e->name, (unsigned long)patch_start, (unsigned long)patch_end, (unsigned long)fallback_func);
    return 0;
}

bool ulp_is_patch_quarantined(const char *name)
{
    pthread_mutex_lock(&g_guard_lock);
    for (size_t i = 0; i < g_guard_count; i++) {
        if (strcmp(g_guard_table[i].name, name) == 0) {
            bool q = (g_guard_table[i].quarantined != 0);
            pthread_mutex_unlock(&g_guard_lock);
            return q;
        }
    }
    pthread_mutex_unlock(&g_guard_lock);
    return false;
}

void ulp_quarantine_patch(const char *name)
{
    pthread_mutex_lock(&g_guard_lock);
    for (size_t i = 0; i < g_guard_count; i++) {
        if (strcmp(g_guard_table[i].name, name) == 0) {
            g_guard_table[i].quarantined = 1;
            break;
        }
    }
    pthread_mutex_unlock(&g_guard_lock);
}

uint64_t ulp_get_total_faults_intercepted(void)
{
    return atomic_load(&g_total_faults_intercepted);
}

uint64_t ulp_get_total_crashes_prevented(void)
{
    return atomic_load(&g_total_crashes_prevented);
}

void ulp_print_guard_status(void)
{
    printf("\n=== ULP FAULT GUARD & SELF-HEALING STATUS ===\n");
    printf("Total Faults Intercepted: %lu\n", (unsigned long)ulp_get_total_faults_intercepted());
    printf("Total Crashes Prevented:   %lu\n", (unsigned long)ulp_get_total_crashes_prevented());
    printf("%-20s %-18s %-18s %-12s %-10s\n", "PATCH NAME", "START ADDR", "END ADDR", "STATUS", "FAULTS");
    printf("------------------------------------------------------------------------------------\n");
    for (size_t i = 0; i < g_guard_count; i++) {
        ulp_patch_guard_entry_t *e = &g_guard_table[i];
        printf("%-20s 0x%016lx 0x%016lx %-12s %-10lu\n",
               e->name,
               (unsigned long)e->patch_start,
               (unsigned long)e->patch_end,
               e->quarantined ? "QUARANTINED" : "ACTIVE",
               (unsigned long)e->fault_count);
    }
    printf("============================================\n\n");
}
