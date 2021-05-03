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

# TODO: Add the x86_64 optimized implementations to the Makefile build system,
#       similarly as it was done for SIKE. The CMake build system already
#       supports compiling the optimized files.
SRCS=aes_ctr_prf.c bike_r3_kem.c decode.c decode_portable.c error.c gf2x_inv.c gf2x_ksqr_portable.c gf2x_mul.c gf2x_mul_base_portable.c gf2x_mul_portable.c sampling.c sampling_portable.c utilities.c
OBJS=$(SRCS:.c=.o)

#WA for GCC 4.8.5 bug.
CFLAGS += -Wno-missing-braces -Wno-missing-field-initializers -I../../

.PHONY : all
all: $(OBJS)

CFLAGS_LLVM = -emit-llvm -c -g \
              -std=c99 -fgnu89-inline -D_POSIX_C_SOURCE=200809L -D_FORTIFY_SOURCE=2 \
              -I$(LIBCRYPTO_ROOT)/include/ -I../../api/ -I../../

BCS=$(addprefix $(BITCODE_DIR), $(SRCS:.c=.bc))

.PHONY : bc
bc: $(BCS)
