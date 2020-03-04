# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0"

.DEFAULT_GOAL := all

include ../../s2n.mk

SRCS=$(wildcard *.c)
OBJS=$(SRCS:.c=.o)

#WA for GCC 4.8.5 bug.
CFLAGS += -Wno-missing-braces -Wno-missing-field-initializers -I../../

.PHONY : all
all: $(OBJS)

CFLAGS_LLVM = -emit-llvm -c -g \
              -std=c99 -fgnu89-inline -D_POSIX_C_SOURCE=200809L -D_FORTIFY_SOURCE=2 \
              -I$(LIBCRYPTO_ROOT)/include/ -I../../api/ -I../../

BCS_1=utilities.bc decode.bc bike_r1_kem.bc \
    converts_portable.bc secure_decode_portable.bc \
    openssl_utils.bc aes_ctr_prf.bc parallel_hash.bc \
    sampling_portable.bc sampling.bc
BCS=$(addprefix $(BITCODE_DIR), $(BCS_1))

.PHONY : bc
bc: $(BCS)
