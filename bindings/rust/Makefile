SHELL := /bin/bash

all: RUSTBINDINGS target/release/deps/s2nc-% 

.EXPORT_ALL_VARIABLES:
OPENSSL_DIR = $(value LIBCRYPTO_ROOT)

RUSTBINDINGS = ./s2n-tls-sys/src/api.rs

RUSTBINDINGS: generate/src/main.rs 
	@OPENSSL_DIR=$(OPENSSL_DIR) ./generate.sh

target/release/deps/s2nc-%: RUSTBINDINGS
	@OPENSSL_DIR=$(OPENSSL_DIR) cargo bench --no-run
