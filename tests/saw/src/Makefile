LL ?= llvm-link

s2n/Makefile:
	git clone https://github.com/awslabs/s2n.git

# NB: This is specialized to an OSX Homebrew installation of OpenSSL
s2n/crypto/s2n_hmac.o: s2n/Makefile
	make -C s2n CC=clang CFLAGS="-emit-llvm -I../libcrypto-root/include -I../api -I.. -I/usr/local/opt/openssl/include" libs

hmac.bc: s2n/crypto/s2n_hmac.o
	${LL} -o $@ s2n/crypto/s2n_hmac.o s2n/crypto/s2n_hash.o
