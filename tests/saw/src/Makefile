# NB: This is specialized to an OSX Homebrew installation of LLVM
LL ?= /usr/local/opt/llvm/bin/llvm-link
CLANG ?= /usr/local/opt/llvm/bin/clang

OBJS = s2n/crypto/s2n_hmac.o s2n/crypto/s2n_hash.o s2n/utils/s2n_safety.o

s2n/Makefile:
	git clone https://github.com/awslabs/s2n.git

# NB: This is specialized to an OSX Homebrew installation of OpenSSL
s2n/crypto/%.o: s2n/crypto/%.c
	make s2n/Makefile
	make -C s2n/crypto CC=${CLANG} CFLAGS="-emit-llvm -I../libcrypto-root/include -I../api -I..  -I/usr/local/opt/openssl/include" $(notdir $@)

s2n/utils/%.o: s2n/utils/%.c
	make s2n/Makefile
	make -C s2n/utils CC=${CLANG} CFLAGS="-emit-llvm -I../libcrypto-root/include -I../api -I..  -I/usr/local/opt/openssl/include" $(notdir $@)

hmac.bc: ${OBJS}
	${LL} -o $@ $+



clean:
	rm -f hmac.bc
	make -C s2n clean
