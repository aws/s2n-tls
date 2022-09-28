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

# Kyber Round-3 code has several different optimizations
# which require specific compiler flags to be supported
# by the compiler. The flags are set in the s2n_pq_asm.mk
# file and used here to compile the optimized code files.

SRCS=kyber512r3_cbd.c kyber512r3_fips202.c kyber512r3_indcpa.c kyber512r3_kem.c kyber512r3_ntt.c kyber512r3_poly.c kyber512r3_polyvec.c kyber512r3_reduce.c kyber512r3_symmetric-shake.c
OBJS=$(SRCS:.c=.o)

AVX2_SRCS=kyber512r3_cbd_avx2.c kyber512r3_consts_avx2.c kyber512r3_fips202x4_avx2.c kyber512r3_indcpa_avx2.c kyber512r3_poly_avx2.c kyber512r3_polyvec_avx2.c kyber512r3_rejsample_avx2.c KeccakP-1600-times4-SIMD256_avx2.c
AVX2_ASM_SRCS=kyber512r3_basemul_avx2.S kyber512r3_fq_avx2.S kyber512r3_invntt_avx2.S kyber512r3_ntt_avx2.S kyber512r3_shuffle_avx2.S


ifeq ($(KYBER512R3_AVX2_BMI2_SUPPORTED), 0)
  CFLAGS += -DS2N_KYBER512R3_AVX2_BMI2
  CFLAGS_LLVM += -DS2N_KYBER512R3_AVX2_BMI2

  AVX2_OBJS=$(AVX2_SRCS:.c=.o)
  AVX2_ASM_OBJS=$(AVX2_ASM_SRCS:.S=.o)

  KYBER512R3_AVX2_BMI2_FLAGS= -mavx2 -mbmi2
  $(AVX2_SRCS): CFLAGS += $(KYBER512R3_AVX2_BMI2_FLAGS)
  $(AVX2_OBJS): CFLAGS += $(KYBER512R3_AVX2_BMI2_FLAGS)
  $(AVX2_ASM_OBJS): CFLAGS += $(KYBER512R3_AVX2_BMI2_FLAGS)
endif

#WA for GCC 4.8.5 bug.
CFLAGS += -Wno-missing-braces -Wno-missing-field-initializers -I../../

ifeq ($(KYBER512R3_AVX2_BMI2_SUPPORTED), 0)
    .PHONY : all
    all: $(OBJS) $(AVX2_OBJS) $(AVX2_ASM_OBJS)
else
    .PHONY : all
    all: $(OBJS)
endif

CFLAGS_LLVM = -emit-llvm -c -g \
              -std=c99 -fgnu89-inline -D_POSIX_C_SOURCE=200809L -D_FORTIFY_SOURCE=2 \
              -I$(LIBCRYPTO_ROOT)/include/ -I../../api/ -I../../

BCS=$(addprefix $(BITCODE_DIR), $(SRCS:.c=.bc))
ifeq ($(KYBER512R3_AVX2_BMI2_SUPPORTED), 0)
    AVX2_BCS=$(addprefix $(BITCODE_DIR), $(AVX2_SRCS:.c=.bc))
    AVX2_ASM_BCS=$(addprefix $(BITCODE_DIR), $(AVX2_ASM_SRCS:.S=.bc))
endif

$(BCS): CFLAGS_LLVM += $(KYBER512R3_AVX2_BMI2_FLAGS)
ifeq ($(KYBER512R3_AVX2_BMI2_SUPPORTED), 0)
    $(AVX2_BCS): CFLAGS_LLVM += $(KYBER512R3_AVX2_BMI2_FLAGS)
    $(AVX2_ASM_BCS): CFLAGS_LLVM += $(KYBER512R3_AVX2_BMI2_FLAGS)
endif

ifeq ($(KYBER512R3_AVX2_BMI2_SUPPORTED), 0)
    .PHONY : bc
    bc: $(BCS) $(AVX2_BCS) $(AVX2_ASM_BCS)
else
    .PHONY : bc
    bc: $(BCS)
endif
