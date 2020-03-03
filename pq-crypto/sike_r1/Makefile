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

SRCS=fp_generic_r1.c P503_r1.c sike_r1_kem.c fips202_r1.c
OBJS=$(SRCS:.c=.o)

BCS_1=fp_generic_r1.bc P503_r1.bc sike_r1_kem.bc fips202_r1.bc
BCS=$(addprefix $(BITCODE_DIR), $(BCS_1))

.PHONY : all
all: $(OBJS)

.PHONY : bc
bc: $(BCS)

include ../../s2n.mk
