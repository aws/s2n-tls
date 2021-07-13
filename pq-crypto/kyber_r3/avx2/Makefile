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

include ../../../s2n.mk
include ../../s2n_pq_asm.mk

# Kyber Round-3 code has several different optimizations
# which require specific compiler flags to be supported
# by the compiler. The flags are set in the s2n_pq_asm.mk
# file and used here to compile the optimized code files.

SRCS=kyber512r3_cbd_avx2.c kyber512r3_consts_avx2.c kyber512r3_fips202x4_avx2.c kyber512r3_indcpa_avx2.c kyber512r3_poly_avx2.c kyber512r3_polyvec_avx2.c kyber512r3_rejsample_avx2.c
ASM_SRCS=kyber512r3_basemul_avx2.S kyber512r3_fq_avx2.S kyber512r3_invntt_avx2.S kyber512r3_ntt_avx2.S kyber512r3_shuffle_avx2.S

OBJS=$(SRCS:.c=.o)
ASM_OBJS=$(ASM_SRCS:.S=.o)

$(OBJS): CFLAGS += $(KYBER512R3_AVX2_BMI2_FLAGS)
$(ASM_OBJS): CFLAGS += $(KYBER512R3_AVX2_BMI2_FLAGS)

#WA for GCC 4.8.5 bug.
CFLAGS += -Wno-missing-braces -Wno-missing-field-initializers -I../../

.PHONY : all
all: $(OBJS) $(ASM_OBJS)

CFLAGS_LLVM = -emit-llvm -c -g \
              -std=c99 -fgnu89-inline -D_POSIX_C_SOURCE=200809L -D_FORTIFY_SOURCE=2 \
              -I$(LIBCRYPTO_ROOT)/include/ -I../../api/ -I../../

BCS=$(addprefix $(BITCODE_DIR), $(SRCS:.c=.bc))
ASM_BCS=$(addprefix $(BITCODE_DIR), $(ASM_SRCS:.c=.bc))

$(BCS): CFLAGS_LLVM += $(KYBER512R3_AVX2_BMI2_FLAGS)
$(ASM_BCS): CFLAGS_LLVM += $(KYBER512R3_AVX2_BMI2_FLAGS)

.PHONY : bc
bc: $(BCS) $(ASM_BCS)