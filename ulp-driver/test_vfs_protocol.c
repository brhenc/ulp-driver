#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <poll.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "ulp_uapi.h"

int main(void)
{
    int fd;
    ssize_t n;
    struct ulp_cmd_v1 cmd;
    struct ulp_event ev;
    struct pollfd pfd;

    printf("=== ulp-driver /dev/ulp protocol test ===\n");

    fd = open("/dev/ulp", O_RDWR | O_NONBLOCK);
    if (fd < 0) {
        perror("[-] Failed to open /dev/ulp");
        return 1;
    }
    printf("[+] Successfully opened /dev/ulp with Mode 0600\n");

    /* 1. Test unauthenticated write while LOCKED (Must Fail with -EPERM) */
    memset(&cmd, 0, sizeof(cmd));
    cmd.size = sizeof(cmd);
    cmd.cmd_type = ULP_CMD_APPLY_PATCH;
    cmd.target_pid = 1234;
    cmd.target_vaddr = 0x555555554000;
    cmd.patch_vaddr = 0x7ffff7fc0000;
    cmd.tramp_len = 16;
    strcpy(cmd.patch_name, "unauthorized_test");

    n = write(fd, &cmd, sizeof(cmd));
    if (n < 0 && errno == EPERM) {
        printf("[+] SUCCESS: Direct apply while LOCKED was rejected with -EPERM as required!\n");
    } else {
        printf("[-] ERROR: Expected -EPERM while locked, got n=%ld, errno=%d (%s)\n", (long)n, errno, strerror(errno));
        close(fd);
        return 1;
    }

    /* 2. Test Arming the Driver (ULP_CMD_ARM) */
    memset(&cmd, 0, sizeof(cmd));
    cmd.size = sizeof(cmd);
    cmd.cmd_type = ULP_CMD_ARM;
    cmd.ttl_seconds = 30;

    n = write(fd, &cmd, sizeof(cmd));
    if (n == sizeof(cmd)) {
        printf("[+] SUCCESS: Driver armed for maintenance (TTL: 30s)!\n");
    } else {
        printf("[-] ERROR: Failed to arm driver: n=%ld, errno=%d (%s)\n", (long)n, errno, strerror(errno));
        close(fd);
        return 1;
    }

    /* 3. Test poll() and read() for Telemetry Events */
    pfd.fd = fd;
    pfd.events = POLLIN;
    pfd.revents = 0;

    int pr = poll(&pfd, 1, 1000);
    if (pr > 0 && (pfd.revents & POLLIN)) {
        n = read(fd, &ev, sizeof(ev));
        if (n == sizeof(ev)) {
            printf("[+] SUCCESS: poll() woke up! Telemetry Event received: type=%u, pid=%u, comm='%s', msg='%s'\n",
                   ev.event_type, ev.pid, ev.comm, ev.msg);
        } else {
            printf("[-] ERROR: read returned %ld bytes\n", (long)n);
        }
    } else {
        printf("[-] ERROR: poll timed out waiting for armed event\n");
    }

    /* 4. Test Disarming the Driver (ULP_CMD_DISARM) */
    memset(&cmd, 0, sizeof(cmd));
    cmd.size = sizeof(cmd);
    cmd.cmd_type = ULP_CMD_DISARM;

    n = write(fd, &cmd, sizeof(cmd));
    if (n == sizeof(cmd)) {
        printf("[+] SUCCESS: Driver disarmed by operator into fail-closed LOCKED mode!\n");
    } else {
        printf("[-] ERROR: Failed to disarm driver: n=%ld, errno=%d\n", (long)n, errno);
    }

    /* Read disarm event */
    n = read(fd, &ev, sizeof(ev));
    if (n == sizeof(ev)) {
        printf("[+] SUCCESS: Read Disarm Event: type=%u, msg='%s'\n", ev.event_type, ev.msg);
    }

    close(fd);
    printf("=== /dev/ulp protocol test completed ===\n");
    return 0;
}
