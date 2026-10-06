RUSTC ?= rustc
RUSTFLAGS ?= -O

all: rust_daemon libpatch_rust.so

rust_daemon: rust_daemon.rs
	$(RUSTC) $(RUSTFLAGS) --crate-type bin -o $@ $<

libpatch_rust.so: patch_rust.rs
	$(RUSTC) $(RUSTFLAGS) --crate-type cdylib -o $@ $<

clean:
	rm -f rust_daemon libpatch_rust.so /tmp/ulp_example_rust.sock
