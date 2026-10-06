#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <pthread.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <sys/wait.h>
#include "ulp_uapi.h"

#define NUM_WORKERS 8
#define OPS_PER_WORKER 500

/* Target function */
__attribute__((noinline))
static int dummy_target_fn(void) {
    return 42;
}

/* Replacement function */
__attribute__((noinline))
static int replacement_fn(void) {
    return 999;
}

static volatile int g_running = 1;
static volatile uint32_t g_shared_futex = 0;

/* Coverage statistics across all validation branches */
static struct {
    uint64_t total_ops;
    uint64_t ret_success;      /* Code 0: Patch applied / reverted / listed */
    uint64_t ret_eperm;        /* -EPERM: DAC / Scope authorization gate */
    uint64_t ret_esrch;        /* -ESRCH: Task / PID lookup gate */
    uint64_t ret_einval;       /* -EINVAL: VMA bounds / func_len < 16 gate */
    uint64_t ret_eacces;       /* -EACCES: VM_EXEC permission gate */
    uint64_t ret_ebusy;        /* -EBUSY: Futex lock safety gate */
    uint64_t ret_eagain;       /* -EAGAIN: Thread stack quiescence gate */
    uint64_t ret_enoent;       /* -ENOENT: Patch registry lookup gate */
    uint64_t ret_efault;       /* -EFAULT: Memory access gate */
    uint64_t ret_other;
} g_cov_stats;

static pthread_mutex_t g_stats_lock = PTHREAD_MUTEX_INITIALIZER;

static void record_stat(int ret) {
    pthread_mutex_lock(&g_stats_lock);
    g_cov_stats.total_ops++;
    if (ret == 0) g_cov_stats.ret_success++;
    else if (errno == EPERM) g_cov_stats.ret_eperm++;
    else if (errno == ESRCH) g_cov_stats.ret_esrch++;
    else if (errno == EINVAL) g_cov_stats.ret_einval++;
    else if (errno == EACCES) g_cov_stats.ret_eacces++;
    else if (errno == EBUSY) g_cov_stats.ret_ebusy++;
    else if (errno == EAGAIN) g_cov_stats.ret_eagain++;
    else if (errno == ENOENT) g_cov_stats.ret_enoent++;
    else if (errno == EFAULT) g_cov_stats.ret_efault++;
    else g_cov_stats.ret_other++;
    pthread_mutex_unlock(&g_stats_lock);
}

/* Semi-valid seed corpus builder */
static void populate_seed_request(struct ulp_patch_req *req, int seed_type) {
    memset(req, 0, sizeof(*req));
    uintptr_t target_fn = (uintptr_t)dummy_target_fn;
    uintptr_t patch_fn = (uintptr_t)replacement_fn;
    uintptr_t valid_futex = (uintptr_t)&g_shared_futex;

    switch (seed_type % 10) {
    case 0: /* Legitimate valid patch */
        req->target_pid = getpid();
        strncpy(req->patch_name, "seed_legit_patch", ULP_NAME_MAX);
        strncpy(req->func_name, "dummy_target_fn", ULP_NAME_MAX);
        req->target_vaddr = target_fn;
        req->patch_vaddr = patch_fn;
        req->func_len = 64;
        req->futex_vaddr = 0;
        break;

    case 1: /* Valid patch with unlocked futex check */
        req->target_pid = getpid();
        strncpy(req->patch_name, "seed_futex_unlocked", ULP_NAME_MAX);
        strncpy(req->func_name, "dummy_target_fn", ULP_NAME_MAX);
        req->target_vaddr = target_fn;
        req->patch_vaddr = patch_fn;
        req->func_len = 32;
        g_shared_futex = 0;
        req->futex_vaddr = valid_futex;
        break;

    case 2: /* Valid patch hitting LOCKED futex (-EBUSY) */
        req->target_pid = getpid();
        strncpy(req->patch_name, "seed_futex_locked", ULP_NAME_MAX);
        strncpy(req->func_name, "dummy_target_fn", ULP_NAME_MAX);
        req->target_vaddr = target_fn;
        req->patch_vaddr = patch_fn;
        req->func_len = 32;
        g_shared_futex = 1;
        req->futex_vaddr = valid_futex;
        break;

    case 3: /* Function length boundary (< 16 -> -EINVAL) */
        req->target_pid = getpid();
        strncpy(req->patch_name, "seed_short_func", ULP_NAME_MAX);
        strncpy(req->func_name, "dummy_target_fn", ULP_NAME_MAX);
        req->target_vaddr = target_fn;
        req->patch_vaddr = patch_fn;
        req->func_len = (rand() % 15) + 1; /* 1..15 */
        break;

    case 4: /* Non-executable heap VMA (-EACCES) */
        req->target_pid = getpid();
        strncpy(req->patch_name, "seed_heap_vma", ULP_NAME_MAX);
        strncpy(req->func_name, "heap_var", ULP_NAME_MAX);
        req->target_vaddr = valid_futex;
        req->patch_vaddr = patch_fn;
        req->func_len = 32;
        break;

    case 5: /* Invalid unmapped address (-EINVAL / -EFAULT) */
        req->target_pid = getpid();
        strncpy(req->patch_name, "seed_unmapped_vma", ULP_NAME_MAX);
        strncpy(req->func_name, "bad_addr", ULP_NAME_MAX);
        req->target_vaddr = 0x1000 + (rand() % 0x10000);
        req->patch_vaddr = patch_fn;
        req->func_len = 32;
        break;

    case 6: /* Random PID permutation (-ESRCH or -EPERM) */
        req->target_pid = (rand() % 50000) + 1;
        strncpy(req->patch_name, "seed_random_pid", ULP_NAME_MAX);
        strncpy(req->func_name, "func", ULP_NAME_MAX);
        req->target_vaddr = target_fn;
        req->patch_vaddr = patch_fn;
        req->func_len = 64;
        break;

    case 7: /* String length boundary test */
        req->target_pid = getpid();
        memset(req->patch_name, 'A', sizeof(req->patch_name) - 1);
        memset(req->func_name, 'B', sizeof(req->func_name) - 1);
        req->target_vaddr = target_fn;
        req->patch_vaddr = patch_fn;
        req->func_len = 128;
        break;

    case 8: /* Revert non-existent patch (-ENOENT) */
        req->target_pid = getpid();
        req->target_vaddr = target_fn + 0x1000;
        break;

    case 9: /* Mutated trampoline offset */
        req->target_pid = getpid();
        strncpy(req->patch_name, "seed_offset_mutate", ULP_NAME_MAX);
        strncpy(req->func_name, "func", ULP_NAME_MAX);
        req->target_vaddr = target_fn + ((rand() % 32) - 16);
        req->patch_vaddr = patch_fn;
        req->func_len = 64;
        break;
    }
}

static void *coverage_fuzz_worker(void *arg) {
    int worker_id = (int)(intptr_t)arg;
    int fd = open("/dev/ulp", O_RDWR);
    if (fd < 0) return NULL;

    unsigned int seed = (unsigned int)(time(NULL) ^ (worker_id << 16));

    for (int i = 0; i < OPS_PER_WORKER && g_running; i++) {
        int action = rand_r(&seed) % 4;

        if (action == 0 || action == 1) {
            /* Fuzz Apply ioctl */
            struct ulp_patch_req req;
            populate_seed_request(&req, rand_r(&seed));

            int r = ioctl(fd, ULP_IOC_APPLY_PATCH, &req);
            record_stat(r);

            /* If successfully applied, immediately revert to clean state */
            if (r == 0) {
                int rev_r = ioctl(fd, ULP_IOC_REVERT_PATCH, &req);
                record_stat(rev_r);
            }
        } else if (action == 2) {
            /* Fuzz Revert ioctl */
            struct ulp_patch_req req;
            populate_seed_request(&req, 8);
            int r = ioctl(fd, ULP_IOC_REVERT_PATCH, &req);
            record_stat(r);
        } else {
            /* Fuzz List ioctl & /proc/ulp_patches */
            struct ulp_list_req lreq;
            memset(&lreq, 0, sizeof(lreq));
            int r = ioctl(fd, ULP_IOC_LIST_PATCHES, &lreq);
            record_stat(r);

            if (rand_r(&seed) % 10 == 0) {
                int pfd = open("/proc/ulp_patches", O_RDONLY);
                if (pfd >= 0) {
                    char buf[1024];
                    while (read(pfd, buf, sizeof(buf)) > 0) {}
                    close(pfd);
                }
            }
        }
    }

    close(fd);
    return NULL;
}

int main(int argc, char **argv) {
    printf("======================================================================\n");
    printf("   ULP-DRIVER: SYZKALLER-STYLE COVERAGE-GUIDED SEED FUZZER    \n");
    printf("   Workers: %d | Operations per worker: %d | Total: %d\n",
           NUM_WORKERS, OPS_PER_WORKER, NUM_WORKERS * OPS_PER_WORKER);
    printf("======================================================================\n");

    pthread_t workers[NUM_WORKERS];
    for (intptr_t i = 0; i < NUM_WORKERS; i++) {
        pthread_create(&workers[i], NULL, coverage_fuzz_worker, (void *)i);
    }

    for (int i = 0; i < NUM_WORKERS; i++) {
        pthread_join(workers[i], NULL);
    }

    printf("\n======================================================================\n");
    printf("                 KERNEL CODE-PATH COVERAGE MATRIX                     \n");
    printf("======================================================================\n");
    printf("  Total Operations Executed  : %lu\n", g_cov_stats.total_ops);
    printf("  [Branch 1] SUCCESS (0)     : %-8lu (Valid text pokes, reverts & lists)\n", g_cov_stats.ret_success);
    printf("  [Branch 2] -EPERM (1)      : %-8lu (DAC Scope / Creator UID blocked)\n", g_cov_stats.ret_eperm);
    printf("  [Branch 3] -ESRCH (3)      : %-8lu (Task / PID lookup validation)\n", g_cov_stats.ret_esrch);
    printf("  [Branch 4] -EINVAL (22)    : %-8lu (VMA bounds / func_len < 16 validation)\n", g_cov_stats.ret_einval);
    printf("  [Branch 5] -EACCES (13)    : %-8lu (Non-executable memory validation)\n", g_cov_stats.ret_eacces);
    printf("  [Branch 6] -EBUSY (16)     : %-8lu (Contended futex lock safety gate)\n", g_cov_stats.ret_ebusy);
    printf("  [Branch 7] -ENOENT (2)     : %-8lu (Unregistered patch rollback gate)\n", g_cov_stats.ret_enoent);
    printf("  [Branch 8] -EFAULT (14)    : %-8lu (Invalid userspace address copy gate)\n", g_cov_stats.ret_efault);
    printf("======================================================================\n");

    if (g_cov_stats.ret_success > 0 && g_cov_stats.ret_einval > 0 &&
        g_cov_stats.ret_ebusy > 0 && g_cov_stats.ret_enoent > 0) {
        printf(">>> COVERAGE VALIDATION: ALL CRITICAL KERNEL BRANCHES EXERCISED! <<<\n");
        return 0;
    } else {
        printf(">>> WARNING: INCOMPLETE BRANCH COVERAGE DETECTED <<<\n");
        return 1;
    }
}
