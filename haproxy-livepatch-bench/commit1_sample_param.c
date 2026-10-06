#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <syslog.h>

/* HAProxy structures for sample converter */
struct buffer {
    size_t size;
    char *area;
    size_t data;
    size_t head;
};

struct arg {
    uint8_t type;
    union {
        int64_t sint;
        struct buffer str;
        void *ptr;
    } data;
};

#define ARGT_STR 1

/* Upstream Commit ccd8e5b57: make param converter support 0xHH control characters */
int livepatch_sample_conv_param_check(struct arg *arg, void *conv,
                                      const char *file, int line, char **err)
{
    syslog(LOG_INFO, "[ULP-HAPROXY-COMMIT-1] livepatch_sample_conv_param_check executed (support 0xHH control chars)\n");

    if (arg[1].type == ARGT_STR && arg[1].data.str.data == 4 &&
        strncmp(arg[1].data.str.area, "0x", 2) == 0) {
        char *err_str = NULL;
        long val = strtol(arg[1].data.str.area, &err_str, 0);

        if (!err_str || !*err_str) {
            arg[1].data.str.area[0] = (char)val;
            arg[1].data.str.data = 1;
            return 1;
        }
    }

    if (arg[1].type == ARGT_STR && arg[1].data.str.data != 1) {
        return 0;
    }

    return 1;
}
