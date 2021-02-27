#include ../s2n_pq_asm.mk

NISTFLAGS  = -Wno-unused-result -O3 -fomit-frame-pointer -march=native -std=c99 -I$(S2N_ROOT) -I$(S2N_ROOT)/api

#CFLAGS +=  -Wincompatible-pointer-types-discards-qualifiers -I/usr/local/opt/openssl/include


SRCS = rng.c pack_unpack.c poly.c verify.c cbd.c SABER_indcpa.c saber_saber_r2_kem.c
#fips202.c and poly_mul.c are not included as they are covered by Kyber

OBJS=$(SRCS:.c=.o)

.PHONY : all
all: $(OBJS)


HEADERS = SABER_params.h pack_unpack.h poly.h rng.h fips202.h verify.h cbd.h SABER_indcpa.h 

rng.o: rng.c
	$(CC) $(NISTFLAGS) -c rng.c -L$(LIBCRYPTO_ROOT)/lib -I$(LIBCRYPTO_ROOT)/include $(CRYPTO_LIBS) -o $@ 

#fips202.o: fips202.c
#	$(CC) -c $^ -o $@

include ../../s2n.mk
