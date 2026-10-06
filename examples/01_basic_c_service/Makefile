CC ?= gcc
CFLAGS ?= -O2 -Wall -fno-omit-frame-pointer -no-pie
LDFLAGS ?= 

all: target_service patch_payload.so

target_service: target_service.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

patch_payload.so: patch_payload.c
	$(CC) -shared -fPIC -O2 -Wall -o $@ $<

clean:
	rm -f target_service patch_payload.so /tmp/ulp_example_c.sock
