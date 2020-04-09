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

SRCS=fips202.c P434.c
OBJS=$(SRCS:.c=.o)

BCS_1=fips202.bc P434.bc
BCS=$(addprefix $(BITCODE_DIR), $(BCS_1))

.PHONY : all
all: $(OBJS)

.PHONY : bc
bc: $(BCS)

include ../../s2n.mk

# Verify that the ASM code compiles before actually including it in the build.
# Output is directed to /dev/null so it doesn't pollute the console on compilation
# failures that may be expected.
# Note that if compilation is successful, you probably will not see Make re-compile
# fp_x64_asm.S in the logs when it compiles the rest of the sike_r2 code, since the
# object file is up to date. If you're looking to sanity check that the ASM was
# included in the build, you will be able to see fp_x64_asm.o linked at the end
# of the build.
ifndef S2N_NO_PQ_ASM
	TRY_COMPILE_PQ_ASM := $(shell $(CC) -c -o ./fp_x64_asm.o ./fp_x64_asm.S > /dev/null 2>&1; echo $$?)
	ifeq ($(TRY_COMPILE_PQ_ASM), 0)
		ASRC=fp_x64_asm.S
		OBJS+=$(ASRC:.S=.o)

		TRY_COMPILE_PQ_ASM_ADX := $(shell $(CC) -D_ADX_ -c -o ./fp_x64_asm.o ./fp_x64_asm.S > /dev/null 2>&1; echo $$?)
		ifeq ($(TRY_COMPILE_PQ_ASM_ADX), 0)
			CFLAGS += -D_ADX_
		endif
	else
		CFLAGS += -DS2N_NO_PQ_ASM
	endif
endif
