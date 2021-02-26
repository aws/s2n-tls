#include ../s2n_pq_asm.mk

NISTFLAGS  = -Wno-unused-result -O3 -fomit-frame-pointer -march=native -std=c99 -I$(S2N_ROOT) -I$(S2N_ROOT)/api

CFLAGS +=  -Wincompatible-pointer-types-discards-qualifiers


SRCS = pack_unpack.c poly.c verify.c cbd.c SABER_indcpa.c saber_saber_r2_kem.c
#fips202.c and poly_mul.c are not included as they are covered by Kyber

OBJS=$(SRCS:.c=.o)

.PHONY : all
all: $(OBJS)


HEADERS = SABER_params.h pack_unpack.h poly.h rng.h fips202.h verify.h cbd.h SABER_indcpa.h 

test/test_kex.o: $(SRCS) $(HEADERS) rng.o test/test_kex.c
	$(CC) $(CFLAGS) -o $@ $(SRCS) rng.o test/test_kex.c -L$(LIBCRYPTO_ROOT)/lib $(CRYPTO_LIBS) -L/Users/nafea/s2n_build/lib -ls2n

test/PQCgenKAT_kem.o: $(SRCS) $(HEADERS) rng.o test/PQCgenKAT_kem.c 
	$(CC) $(NISTFLAGS) -o $@ $(SRCS) rng.o test/PQCgenKAT_kem.c -L$(LIBCRYPTO_ROOT)/lib $(CRYPTO_LIBS) -L/Users/nafea/s2n_build/lib -ls2n

test/kem.o: $(SRCS) $(HEADERS) rng.o test/kem.c
	$(CC) $(CFLAGS) -o $@ $(SRCS) rng.o test/kem.c -L$(LIBCRYPTO_ROOT)/lib $(CRYPTO_LIBS) -L/Users/nafea/s2n_build/lib -ls2n

rng.o: rng.c
	$(CC) $(NISTFLAGS) -c rng.c -L$(LIBCRYPTO_ROOT)/lib $(CRYPTO_LIBS) -o $@ 

#fips202.o: fips202.c
#	$(CC) -c $^ -o $@

.PHONY: test
test: 
	test/test_kex
	test/PQCgenKAT_kem
	test/kem

include ../../s2n.mk
