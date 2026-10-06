/*
 * ulp-driver: ULP Example 1 - Target C Service
 *
 * A lightweight standalone daemon listening on a UNIX domain socket.
 * Demonstrates livepatchable function interception with 16-byte CET alignment.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <errno.h>

#define SOCKET_PATH "/tmp/ulp_example_c.sock"

static volatile sig_atomic_t g_running = 1;

static void sig_handler(int sig)
{
    (void)sig;
    g_running = 0;
}

/*
 * TARGET FUNCTION: get_service_status
 *
 * Must be non-inlined and aligned to at least 8 bytes (16 bytes recommended)
 * to satisfy ULP natural alignment constraints and prevent torn instruction writes.
 */
__attribute__((noinline, aligned(16)))
const char *get_service_status(void)
{
    return "STATUS: v1.0.0 [UNPATCHED] | mode=standard | rate_limit=100 req/s\n";
}

static int run_client(void)
{
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

    char buf[512];
    ssize_t n = read(sock, buf, sizeof(buf) - 1);
    if (n > 0) {
        buf[n] = '\0';
        printf("%s", buf);
    }
    close(sock);
    return 0;
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

    if (listen(sfd, 16) < 0) {
        perror("listen");
        close(sfd);
        unlink(SOCKET_PATH);
        return 1;
    }

    printf("[target_service] Running on PID %d, listening on %s\n", getpid(), SOCKET_PATH);
    printf("[target_service] get_service_status symbol address: %p\n", (void *)get_service_status);
    fflush(stdout);

    while (g_running) {
        fd_set fds;
        FD_ZERO(&fds);
        FD_SET(sfd, &fds);
        struct timeval tv = { .tv_sec = 1, .tv_usec = 0 };

        int sel = select(sfd + 1, &fds, NULL, NULL, &tv);
        if (sel <= 0)
            continue;

        int cfd = accept(sfd, NULL, NULL);
        if (cfd < 0)
            continue;

        const char *resp = get_service_status();
        write(cfd, resp, strlen(resp));
        close(cfd);
    }

    close(sfd);
    unlink(SOCKET_PATH);
    printf("[target_service] Clean shutdown complete.\n");
    return 0;
}

int main(int argc, char **argv)
{
    if (argc > 1 && strcmp(argv[1], "--query") == 0)
        return run_client();

    return run_server();
}
