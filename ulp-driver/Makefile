obj-m += ulp_driver.o

KDIR ?= /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)
PREFIX ?= /usr/local

all: kmod ulp_ctl ulp_inject ulp_persist libulp_preload.so test_concurrent_ioctls syz_coverage_fuzzer

kmod:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

ulp_ctl: ulp_ctl.c ulp_uapi.h
	gcc -O2 -Wall -o ulp_ctl ulp_ctl.c

ulp_inject: ulp_inject.c
	gcc -O2 -Wall -o ulp_inject ulp_inject.c -ldl

ulp_persist: ulp_persist.c ulp_uapi.h
	gcc -O2 -Wall -o ulp_persist ulp_persist.c -lcrypto

libulp_preload.so: libulp_preload.c ulp_uapi.h
	gcc -shared -fPIC -O2 -Wall -o libulp_preload.so libulp_preload.c -ldl -lcrypto

test_concurrent_ioctls: test_concurrent_ioctls.c ulp_uapi.h
	gcc -O2 -Wall -pthread -o test_concurrent_ioctls test_concurrent_ioctls.c

syz_coverage_fuzzer: syz_coverage_fuzzer.c ulp_uapi.h
	gcc -O2 -Wall -pthread -o syz_coverage_fuzzer syz_coverage_fuzzer.c

# Install the userspace tools and the kernel module (run as root)
install: install-tools install-module

install-tools: ulp_ctl ulp_inject ulp_persist libulp_preload.so
	install -D -m 755 ulp_ctl $(DESTDIR)$(PREFIX)/bin/ulp_ctl
	install -D -m 755 ulp_inject $(DESTDIR)$(PREFIX)/bin/ulp_inject
	install -D -m 755 ulp_persist $(DESTDIR)$(PREFIX)/bin/ulp_persist
	install -D -m 755 libulp_preload.so $(DESTDIR)$(PREFIX)/lib/libulp_preload.so

install-module: kmod
	$(MAKE) -C $(KDIR) M=$(PWD) modules_install
	depmod -a

.PHONY: all kmod clean install install-tools install-module

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
	rm -f ulp_ctl ulp_inject ulp_persist libulp_preload.so test_concurrent_ioctls syz_coverage_fuzzer *.o
