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

SRCS=fips202.c cbd.c polyvec.c reduce.c ntt.c poly.c polyvec.c verify.c sha3_c.c symmetric-fips202.c indcpa.c kyber_r2_kem.c
OBJS=$(SRCS:.c=.o)

BCS_1=fips202.bc cbd.bc polyvec.h reduce.bc ntt.bc poly.bc polyvec.bc verify.bc sha3_c.c symmetric-fips202.bc indcpa.bc kyber_r2_kem.bc
BCS=$(addprefix $(BITCODE_DIR), $(BCS_1))

.PHONY : all
all: $(OBJS)

BCS=$(addprefix $(BITCODE_DIR), $(SRCS:.c=.bc))

.PHONY : bc
bc: $(BCS)

include ../../s2n.mk
