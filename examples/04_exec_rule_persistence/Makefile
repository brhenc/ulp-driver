CC ?= gcc
CFLAGS ?= -O2 -Wall -fno-omit-frame-pointer -no-pie

all: task_worker

task_worker: task_worker.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f task_worker
