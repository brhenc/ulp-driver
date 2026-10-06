obj-m += ulp_driver.o

KDIR ?= /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

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

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
	rm -f ulp_ctl ulp_inject ulp_persist libulp_preload.so test_concurrent_ioctls syz_coverage_fuzzer *.o
