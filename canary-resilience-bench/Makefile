CC ?= gcc
CFLAGS ?= -O2 -Wall -g -fPIC
LDFLAGS ?= -pthread -ldl

all: server_daemon patch_canary.so patch_buggy_fatfinger.so ulp_canary_ctl ulp_inject

server_daemon: server_daemon.c ulp_fault_guard.c ulp_fault_guard.h
	$(CC) $(CFLAGS) -rdynamic -o server_daemon server_daemon.c ulp_fault_guard.c $(LDFLAGS)

patch_canary.so: patch_canary.c
	$(CC) -shared $(CFLAGS) -o patch_canary.so patch_canary.c

patch_buggy_fatfinger.so: patch_buggy_fatfinger.c
	$(CC) -shared $(CFLAGS) -o patch_buggy_fatfinger.so patch_buggy_fatfinger.c

ulp_canary_ctl: ulp_canary_ctl.c
	$(CC) $(CFLAGS) -o ulp_canary_ctl ulp_canary_ctl.c

ulp_inject: ../ulp-driver/ulp_inject.c
	$(CC) $(CFLAGS) -o ulp_inject ../ulp-driver/ulp_inject.c -ldl

clean:
	rm -f server_daemon patch_canary.so patch_buggy_fatfinger.so ulp_canary_ctl ulp_inject *.o
