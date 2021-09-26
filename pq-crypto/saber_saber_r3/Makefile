#include ../s2n_pq_asm.mk
include ../../s2n.mk

#CFLAGS  = -Wall -Wextra -Wmissing-prototypes -Wredundant-decls\
	-O3 -fomit-frame-pointer -march=native 
NISTFLAGS  = -Wno-unused-result -O3 -fomit-frame-pointer -march=native -std=c99 -I$(S2N_ROOT) -I$(S2N_ROOT)/api

SRCS = pack_unpack.c poly.c fips202.c verify.c cbd.c SABER_indcpa.c kem.c
HEADERS = SABER_params.h pack_unpack.h poly.h rng.h fips202.h verify.h cbd.h SABER_indcpa.h 
OBJS=$(SRCS:.c=.o)

.DEFAULT_GOAL := all

.PHONY : all
all: $(OBJS)

#rng.o: rng.c
#	$(CC) $(NISTFLAGS) -c rng.c -lcrypto -o $@ 


