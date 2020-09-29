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

C_SRCS=fips202.c P434.c
C_OBJS=$(C_SRCS:.c=.o)

BCS_1=fips202.bc P434.bc
BCS=$(addprefix $(BITCODE_DIR), $(BCS_1))

.PHONY : sikep434r2_c
sikep434r2_c: $(C_OBJS)

.PHONY : bc
bc: $(BCS)

include ../../s2n.mk
include ../s2n_pq_asm.mk

ifeq ($(TRY_COMPILE_SIKEP434R2_ASM), 0)
.PHONY : sikep434r2_asm
sikep434r2_asm: $(SIKEP434R2_ASM_OBJ)
else
.PHONY : sikep434r2_asm
sikep434r2_asm: ;
endif

.PHONY : try_include_asm
try_include_asm: sikep434r2_asm sikep434r2_c
