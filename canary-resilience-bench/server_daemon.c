#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdatomic.h>
#include <dlfcn.h>
#include "ulp_fault_guard.h"

#define DEFAULT_PORT 9099
#define BUFFER_SIZE 4096

/* Global Metrics */
static _Atomic uint64_t g_total_requests = 0;
static _Atomic uint64_t g_v0_responses = 0;
static _Atomic uint64_t g_v1_canary_responses = 0;
static _Atomic uint64_t g_error_responses = 0;
static volatile bool g_running = true;

/* Dynamic Canary Ratio Setter Hook */
static void (*g_canary_setter_fn)(uint32_t) = NULL;

void ulp_register_canary_setter(void (*setter)(uint32_t))
{
    g_canary_setter_fn = setter;
    printf("[SERVER] Registered live canary tuning hook at %p\n", (void *)setter);
}

/* Fallback Baseline Implementation */
int fallback_service_process_request(const char *request_path, char *response_buf, size_t max_len)
{
    atomic_fetch_add(&g_v0_responses, 1);
    snprintf(response_buf, max_len,
             "HTTP/1.1 200 OK\r\n"
             "Content-Type: application/json\r\n"
             "X-Engine-Version: V0-Original\r\n"
             "X-Fault-Recovered: true\r\n"
             "Connection: close\r\n\r\n"
             "{\"status\":\"success\",\"version\":\"V0-Original\",\"recovered\":true}\n");
    return 0;
}

/*
 * Core Target Function to be Livepatched
 * Must be aligned and padded for in-place trampoline injection
 */
__attribute__((noinline, aligned(64)))
int service_process_request(const char *request_path, char *response_buf, size_t max_len)
{
    atomic_fetch_add(&g_v0_responses, 1);
    snprintf(response_buf, max_len,
             "HTTP/1.1 200 OK\r\n"
             "Content-Type: application/json\r\n"
             "X-Engine-Version: V0-Original\r\n"
             "Connection: close\r\n\r\n"
             "{\"status\":\"success\",\"version\":\"V0-Original\",\"engine\":\"ulp-driver-V0\"}\n");
    return 0;
}

/* Worker Thread to Handle Client Connection */
static void *client_worker(void *arg)
{
    int client_fd = (intptr_t)arg;
    char rx_buf[BUFFER_SIZE];
    char tx_buf[BUFFER_SIZE];

    ssize_t bytes_read = read(client_fd, rx_buf, sizeof(rx_buf) - 1);
    if (bytes_read > 0) {
        rx_buf[bytes_read] = '\0';
        atomic_fetch_add(&g_total_requests, 1);

        if (strstr(rx_buf, "GET /stats") || strstr(rx_buf, "GET /metrics")) {
            /* Stats / Telemetry Endpoint */
            uint64_t total = atomic_load(&g_total_requests);
            uint64_t v0 = atomic_load(&g_v0_responses);
            uint64_t v1 = atomic_load(&g_v1_canary_responses);
            uint64_t err = atomic_load(&g_error_responses);
            uint64_t faults = ulp_get_total_faults_intercepted();
            uint64_t prevented = ulp_get_total_crashes_prevented();

            snprintf(tx_buf, sizeof(tx_buf),
                     "HTTP/1.1 200 OK\r\n"
                     "Content-Type: application/json\r\n"
                     "Connection: close\r\n\r\n"
                     "{\"total_requests\":%lu,\"v0_responses\":%lu,\"v1_canary_responses\":%lu,"
                     "\"error_responses\":%lu,\"faults_intercepted\":%lu,\"crashes_prevented\":%lu}\n",
                     total, v0, v1, err, faults, prevented);
        } else if (strstr(rx_buf, "GET /set_canary?ratio=")) {
            /* Dynamic Runtime Canary Ratio Tuning */
            char *p = strstr(rx_buf, "ratio=");
            uint32_t ratio = 100;
            if (p) ratio = (uint32_t)atoi(p + 6);

            if (g_canary_setter_fn) {
                g_canary_setter_fn(ratio);
            }

            snprintf(tx_buf, sizeof(tx_buf),
                     "HTTP/1.1 200 OK\r\n"
                     "Content-Type: application/json\r\n"
                     "Connection: close\r\n\r\n"
                     "{\"status\":\"success\",\"canary_ratio_bp\":%u}\n", ratio);
        } else {
            /* Execute livepatchable business call within MULTICS Resilient Fault Frame */
            ULP_GUARDED_CALL(
                service_process_request(rx_buf, tx_buf, sizeof(tx_buf)),
                fallback_service_process_request(rx_buf, tx_buf, sizeof(tx_buf))
            );

            if (strstr(tx_buf, "V1-Canary")) {
                atomic_fetch_add(&g_v1_canary_responses, 1);
            }
        }

        write(client_fd, tx_buf, strlen(tx_buf));
    }

    close(client_fd);
    return NULL;
}

int main(int argc, char **argv)
{
    int port = DEFAULT_PORT;
    if (argc > 1) {
        port = atoi(argv[1]);
    }

    printf("=========================================================\n");
    printf("  ulp-driver: High-Availability Edge Server\n");
    printf("  PID: %d | Port: %d\n", getpid(), port);
    printf("  Address of service_process_request:          %p\n", (void *)service_process_request);
    printf("  Address of fallback_service_process_request: %p\n", (void *)fallback_service_process_request);
    printf("=========================================================\n");

    /* 1. Arm ULP MULTICS Crash Resilience Engine */
    if (ulp_init_fault_guard() < 0) {
        fprintf(stderr, "[-] Warning: Failed to initialize ULP Fault Guard\n");
    }

    /* 2. Bind & Listen on TCP Socket */
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        perror("socket failed");
        return 1;
    }

    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt));

    struct sockaddr_in address;
    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(port);

    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("bind failed");
        close(server_fd);
        return 1;
    }

    if (listen(server_fd, 1024) < 0) {
        perror("listen failed");
        close(server_fd);
        return 1;
    }

    printf("[+] Server listening on 0.0.0.0:%d. Ready for traffic & livepatches.\n", port);
    fflush(stdout);

    while (g_running) {
        struct sockaddr_in client_addr;
        socklen_t addr_len = sizeof(client_addr);
        int client_fd = accept(server_fd, (struct sockaddr *)&client_addr, &addr_len);
        if (client_fd < 0) {
            if (errno == EINTR) continue;
            perror("accept failed");
            break;
        }

        pthread_t tid;
        pthread_attr_t attr;
        pthread_attr_init(&attr);
        pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

        if (pthread_create(&tid, &attr, client_worker, (void *)(intptr_t)client_fd) != 0) {
            close(client_fd);
        }
        pthread_attr_destroy(&attr);
    }

    close(server_fd);
    return 0;
}
