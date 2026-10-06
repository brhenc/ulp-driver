CC ?= gcc
CFLAGS ?= -O2 -Wall -g -fPIC

all: patch_haproxy_canary.so patch_haproxy_buggy.so

patch_haproxy_canary.so: patch_haproxy_canary.c
	$(CC) -shared $(CFLAGS) -o patch_haproxy_canary.so patch_haproxy_canary.c

patch_haproxy_buggy.so: patch_haproxy_buggy.c
	$(CC) -shared $(CFLAGS) -o patch_haproxy_buggy.so patch_haproxy_buggy.c

clean:
	rm -f patch_haproxy_canary.so patch_haproxy_buggy.so *.o
