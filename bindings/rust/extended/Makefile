SHELL := /bin/bash

all: clean s2n-tls-sys/src/api.rs target/release/deps/s2nc-%

target/release/deps/s2nc-%:
	cargo bench --no-run

s2n-tls-sys/src/api.rs:
	./generate.sh

.PHONY: clean
clean:
	@cargo clean
	@rm -f s2n-tls-sys/src/api.rs target/release/deps/s2nc-* target/release/deps/s2nd-*
