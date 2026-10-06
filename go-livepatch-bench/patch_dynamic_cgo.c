#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <string.h>

struct go_string {
    const char *ptr;
    int64_t len;
};

static const char g_cgo_msg[] = "LIVEPATCHED_DYNAMIC_CGO_SERVICE";

struct go_string livepatch_GetServiceStatus(void)
{
    struct go_string s;
    s.ptr = g_cgo_msg;
    s.len = sizeof(g_cgo_msg) - 1;
    return s;
}
