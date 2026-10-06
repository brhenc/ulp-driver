#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>

/**
 * ULP Live Socket Backlog Expansion Helper
 * ========================================
 * Safely inspects the target process's listening sockets and updates
 * sk->sk_max_ack_backlog (Send-Q in `ss -tlpn`) without interrupting
 * active epoll/poll loops or corrupting worker thread execution.
 */
void update_socket_backlog(int new_backlog) {
    for (int fd = 0; fd < 1024; fd++) {
        struct sockaddr_in addr;
        socklen_t len = sizeof(addr);
        if (getsockname(fd, (struct sockaddr *)&addr, &len) == 0) {
            if (addr.sin_family == AF_INET && ntohs(addr.sin_port) == 3306) {
                int res = listen(fd, new_backlog);
                fprintf(stderr, "[ULP-BACKLOG] Updated listening fd=%d (Port 3306) to backlog=%d (res=%d)\n",
                        fd, new_backlog, res);
                return;
            }
        }
    }
}

__attribute__((constructor)) void init(void) {
    // Dynamically expand socket listen backlog to 300
    update_socket_backlog(300);
}
