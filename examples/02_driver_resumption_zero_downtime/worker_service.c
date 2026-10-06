/*
 * ulp-driver: ULP Example 2 - Resilient Worker Service
 *
 * Demonstrates zero-downtime userspace continuity while the ULP kernel driver
 * is unloaded, upgraded, or reloaded with state resumption.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <errno.h>

#define SOCKET_PATH "/tmp/ulp_example_resumption.sock"

static volatile sig_atomic_t g_running = 1;

static void sig_handler(int sig)
{
    (void)sig;
    g_running = 0;
}

/*
 * TARGET FUNCTION: process_work_unit
 *
 * 16-byte aligned and non-inlined for atomic trampoline replacement.
 */
__attribute__((noinline, aligned(16)))
const char *process_work_unit(int unit_id)
{
    static char buf[256];
    snprintf(buf, sizeof(buf), "RESULT: unit=%d | engine=v1_standard | status=nominal\n", unit_id);
    return buf;
}

static int run_client(int count)
{
    int errors = 0;
    for (int i = 1; i <= count; i++) {
        int sock = socket(AF_UNIX, SOCK_STREAM, 0);
        if (sock < 0) {
            perror("socket");
            return 1;
        }

        struct sockaddr_un addr;
        memset(&addr, 0, sizeof(addr));
        addr.sun_family = AF_UNIX;
        strncpy(addr.sun_path, SOCKET_PATH, sizeof(addr.sun_path) - 1);

        if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
            perror("connect");
            close(sock);
            return 1;
        }

        char req_buf[32];
        snprintf(req_buf, sizeof(req_buf), "%d\n", i);
        write(sock, req_buf, strlen(req_buf));

        char resp_buf[256];
        ssize_t n = read(sock, resp_buf, sizeof(resp_buf) - 1);
        if (n > 0) {
            resp_buf[n] = '\0';
            printf("%s", resp_buf);
        } else {
            errors++;
        }
        close(sock);
        usleep(10000); /* 10ms pacing */
    }
    return errors;
}

static int run_server(void)
{
    signal(SIGTERM, sig_handler);
    signal(SIGINT, sig_handler);

    unlink(SOCKET_PATH);

    int sfd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sfd < 0) {
        perror("socket");
        return 1;
    }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, SOCKET_PATH, sizeof(addr.sun_path) - 1);

    if (bind(sfd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind");
        close(sfd);
        return 1;
    }

    if (listen(sfd, 32) < 0) {
        perror("listen");
        close(sfd);
        unlink(SOCKET_PATH);
        return 1;
    }

    printf("[worker_service] PID %d listening on %s\n", getpid(), SOCKET_PATH);
    printf("[worker_service] Target function address: %p\n", (void *)process_work_unit);
    fflush(stdout);

    while (g_running) {
        fd_set fds;
        FD_ZERO(&fds);
        FD_SET(sfd, &fds);
        struct timeval tv = { .tv_sec = 0, .tv_usec = 100000 };

        int sel = select(sfd + 1, &fds, NULL, NULL, &tv);
        if (sel <= 0)
            continue;

        int cfd = accept(sfd, NULL, NULL);
        if (cfd < 0)
            continue;

        char in_buf[32] = {0};
        read(cfd, in_buf, sizeof(in_buf) - 1);
        int unit_id = atoi(in_buf);
        if (unit_id <= 0) unit_id = 1;

        const char *resp = process_work_unit(unit_id);
        write(cfd, resp, strlen(resp));
        close(cfd);
    }

    close(sfd);
    unlink(SOCKET_PATH);
    printf("[worker_service] Clean shutdown complete.\n");
    return 0;
}

int main(int argc, char **argv)
{
    if (argc > 1 && strcmp(argv[1], "--query") == 0) {
        int count = (argc > 2) ? atoi(argv[2]) : 1;
        return run_client(count);
    }

    return run_server();
}
