#
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License").
# You may not use this file except in compliance with the License.
# A copy of the License is located at
#
#  http://aws.amazon.com/apache2.0
#
# or in the "license" file accompanying this file. This file is distributed
# on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
# express or implied. See the License for the specific language governing
# permissions and limitations under the License.
#

.DEFAULT_GOAL := all

include ../../s2n.mk
include ../s2n_pq_asm.mk

# BIKE Round-3 code has several different optimizations
# which require specific compiler flags to be supported
# by the compiler. The flags are set in the s2n_pq_asm.mk
# file and used here to compile the optimized code files.

SRCS=aes_ctr_prf.c bike_r3_kem.c decode.c decode_portable.c error.c gf2x_inv.c gf2x_ksqr_portable.c gf2x_mul.c gf2x_mul_base_portable.c gf2x_mul_portable.c sampling.c sampling_portable.c utilities.c
OBJS=$(SRCS:.c=.o)

AVX2_SRCS=$(wildcard *_avx2.c)
AVX2_OBJS=$(AVX2_SRCS:.c=.o)

AVX512_SRCS=$(wildcard *_avx512.c)
AVX512_OBJS=$(AVX512_SRCS:.c=.o)

PCLMUL_SRCS=$(wildcard *_pclmul.c)
PCLMUL_OBJS=$(PCLMUL_SRCS:.c=.o)

VPCLMUL_SRCS=$(wildcard *_vpclmul.c)
VPCLMUL_OBJS=$(VPCLMUL_SRCS:.c=.o)

$(AVX2_OBJS): CFLAGS += $(BIKE_R3_AVX2_FLAGS)
$(AVX512_OBJS): CFLAGS += $(BIKE_R3_AVX512_FLAGS)
$(PCLMUL_OBJS): CFLAGS += $(BIKE_R3_PCLMUL_FLAGS)
$(VPCLMUL_OBJS): CFLAGS += $(BIKE_R3_VPCLMUL_FLAGS)

#WA for GCC 4.8.5 bug.
CFLAGS += -Wno-missing-braces -Wno-missing-field-initializers -I../../

.PHONY : all
all: $(OBJS) $(AVX2_OBJS) $(AVX512_OBJS) $(PCLMUL_OBJS) $(VPCLMUL_OBJS)

CFLAGS_LLVM = -emit-llvm -c -g \
              -std=c99 -fgnu89-inline -D_POSIX_C_SOURCE=200809L -D_FORTIFY_SOURCE=2 \
              -I$(LIBCRYPTO_ROOT)/include/ -I../../api/ -I../../

BCS=$(addprefix $(BITCODE_DIR), $(SRCS:.c=.bc))
AVX2_BCS=$(addprefix $(BITCODE_DIR), $(AVX2_SRCS:.c=.bc))
AVX512_BCS=$(addprefix $(BITCODE_DIR), $(AVX512_SRCS:.c=.bc))
PCLMUL_BCS=$(addprefix $(BITCODE_DIR), $(PCLMUL_SRCS:.c=.bc))
VPCLMUL_BCS=$(addprefix $(BITCODE_DIR), $(VPCLMUL_SRCS:.c=.bc))

$(AVX2_BCS): CFLAGS_LLVM += $(BIKE_R3_AVX2_FLAGS)
$(AVX512_BCS): CFLAGS_LLVM += $(BIKE_R3_AVX512_FLAGS)
$(PCLMUL_BCS): CFLAGS_LLVM += $(BIKE_R3_PCLMUL_FLAGS)
$(VPCLMUL_BCS): CFLAGS_LLVM += $(BIKE_R3_VPCLMUL_FLAGS)

.PHONY : bc
bc: $(BCS) $(AVX2_BCS) $(AVX512_BCS) $(PCLMUL_BCS) $(VPCLMUL_BCS)
