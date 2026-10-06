CC ?= gcc
CFLAGS ?= -shared -fPIC -O2 -Wall -pthread

all: patch_bgp.so

patch_bgp.so: patch_bgp.c frr_shadow.c frr_shadow.h
	$(CC) $(CFLAGS) -o patch_bgp.so patch_bgp.c frr_shadow.c

clean:
	rm -f patch_bgp.so *.o
