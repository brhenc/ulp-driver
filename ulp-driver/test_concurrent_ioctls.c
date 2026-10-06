#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <pthread.h>
#include <stdint.h>
#include <string.h>
#include <sys/wait.h>
#include "ulp_uapi.h"

#define NUM_THREADS 16
#define ITERATIONS_PER_THREAD 200

static volatile int g_running = 1;

static void dummy_func(void) {
    volatile int x = 0;
    x++;
}

static void replacement_func(void) {
    volatile int y = 100;
    y++;
}

static void *stress_worker(void *arg)
{
    int thread_id = (int)(intptr_t)arg;
    int fd = open("/dev/ulp", O_RDWR);
    if (fd < 0) {
        return NULL;
    }

    for (int i = 0; i < ITERATIONS_PER_THREAD && g_running; i++) {
        int op = rand() % 4;

        if (op == 0) {
            /* Random list ioctl */
            struct ulp_list_req lreq;
            memset(&lreq, 0, sizeof(lreq));
            ioctl(fd, ULP_IOC_LIST_PATCHES, &lreq);
        } else if (op == 1) {
            /* Apply to self or non-existent PID */
            struct ulp_patch_req req;
            memset(&req, 0, sizeof(req));
            req.target_pid = (rand() % 2 == 0) ? getpid() : 999999;
            snprintf(req.patch_name, sizeof(req.patch_name), "stress_%d_%d", thread_id, i);
            snprintf(req.func_name, sizeof(req.func_name), "dummy_func");
            req.target_vaddr = (uint64_t)dummy_func;
            req.patch_vaddr = (uint64_t)replacement_func;
            req.func_len = 64; /* valid length */
            ioctl(fd, ULP_IOC_APPLY_PATCH, &req);
        } else if (op == 2) {
            /* Random revert */
            struct ulp_patch_req req;
            memset(&req, 0, sizeof(req));
            req.target_pid = getpid();
            req.target_vaddr = (uint64_t)dummy_func;
            ioctl(fd, ULP_IOC_REVERT_PATCH, &req);
        } else {
            /* Read /proc/ulp_patches */
            char buf[512];
            int pfd = open("/proc/ulp_patches", O_RDONLY);
            if (pfd >= 0) {
                while (read(pfd, buf, sizeof(buf)) > 0) {}
                close(pfd);
            }
        }
        usleep(100);
    }

    close(fd);
    return NULL;
}

int main(int argc, char **argv)
{
    printf("=== Starting Multithreaded Concurrency Stress Test (%d threads, %d ops each) ===\n",
           NUM_THREADS, ITERATIONS_PER_THREAD);

    pthread_t threads[NUM_THREADS];
    for (intptr_t i = 0; i < NUM_THREADS; i++) {
        pthread_create(&threads[i], NULL, stress_worker, (void *)i);
    }

    for (int i = 0; i < NUM_THREADS; i++) {
        pthread_join(threads[i], NULL);
    }

    printf("=== Concurrency Stress Test Completed: %d total concurrent operations without kernel crash! ===\n",
           NUM_THREADS * ITERATIONS_PER_THREAD);
    return 0;
}
