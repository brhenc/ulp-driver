CC ?= gcc
CFLAGS ?= -O2 -Wall -fno-omit-frame-pointer -no-pie
LDFLAGS ?= 

all: worker_service worker_patch.so

worker_service: worker_service.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

worker_patch.so: worker_patch.c
	$(CC) -shared -fPIC -O2 -Wall -o $@ $<

clean:
	rm -f worker_service worker_patch.so /tmp/ulp_example_resumption.sock
