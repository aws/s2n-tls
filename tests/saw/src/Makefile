# NB: Here 'LL', 'CLANG', and 'OPENSSL_INC' default to an OSX Homebrew
# installation, but this configuration also works when LLVM and
# OpenSSL are installed in the standard places. For other setups, you
# can override these settings with e.g 'make LL=<path to llvm-link>'.
ifeq (, $(shell which llvm-link))
LL ?= /usr/local/opt/llvm/bin/llvm-link
else
LL ?= llvm-link
endif

ifeq (, $(shell which clang))
CLANG ?= /usr/local/opt/llvm/bin/clang
else
CLANG ?= clang
endif

# If this path does not exist it will simply be ignored by 'clang'.
OPENSSL_INC ?= -I/usr/local/opt/openssl/include

################################################################

OBJS = s2n/crypto/s2n_hmac.o s2n/crypto/s2n_hash.o s2n/utils/s2n_safety.o

.PHONY: all
all: hmac.bc

s2n/Makefile:
	git clone https://github.com/awslabs/s2n.git

s2n/crypto/%.o: s2n/crypto/%.c
	make s2n/Makefile
	make -C s2n/crypto CC=${CLANG} CFLAGS="-emit-llvm -I../libcrypto-root/include -I../api -I.. $(OPENSSL_INC)" $(notdir $@)

s2n/utils/%.o: s2n/utils/%.c
	make s2n/Makefile
	make -C s2n/utils CC=${CLANG} CFLAGS="-emit-llvm -I../libcrypto-root/include -I../api -I.. $(OPENSSL_INC)" $(notdir $@)

hmac.bc: ${OBJS}
	${LL} -o $@ $+

.PHONY: clean
clean:
	rm -f hmac.bc
	rm -rf tmp
	make -C s2n clean

# Make Emacs-format tags.
.PHONY: tmp/TAGS
tmp/TAGS:
	mkdir -p tmp
	: > tmp/TAGS
	find `pwd`/s2n \( -name '*.c' -o -name '*.h' \) -exec etags --append -o tmp/TAGS {} +
