#
# Copyright 2014 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

#WA for GCC 4.8.5 bug.
CFLAGS += -Wno-missing-braces -Wno-missing-field-initializers

# Currently only BIKE1_L1 is supportted in the S2N library!
CFLAGS += -DBIKE_VER=1 -DLEVEL=1 -DCONSTANT_TIME -DUSE_OPENSSL

CFLAGS += -I../../

CFLAGS_LLVM = -emit-llvm -c -g \
              -std=c99 -fgnu89-inline -D_POSIX_C_SOURCE=200809L -D_FORTIFY_SOURCE=2 \
              -I$(LIBCRYPTO_ROOT)/include/ -I../../api/ -I../../ -I../ \
              -DBIKE_VER=1 -DLEVEL=1 -DCONSTANT_TIME -DUSE_OPENSSL

SRCS=$(wildcard *.c)
OBJS=$(SRCS:.c=.o)

BCS_1=utilities.bc decode.bc bike1_l1_kem.bc \
    converts_portable.bc secure_decode_portable.bc \
    openssl_utils.bc aes_ctr_prf.bc parallel_hash.bc \
    sampling_portable.bc sampling.bc
BCS=$(addprefix $(BITCODE_DIR), $(BCS_1))

.PHONY : bc
bc: $(BCS)

.PHONY : all
all: libbike1_l1.a

libbike1_l1.a: ${OBJS}
	$(AR) cru libbike1_l1.a ${OBJS}
	$(RANLIB) libbike1_l1.a

.PHONY : clean
clean:
	${MAKE} decruft
