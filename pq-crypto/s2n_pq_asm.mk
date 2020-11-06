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

# To ensure CPU compatibility, try to compile all ASM code before including it in the build.
TRY_COMPILE_SIKEP434R2_ASM = -1

ifndef S2N_NO_PQ_ASM
	# sikep434r2
	SIKEP434R2_ASM_SRC := $(shell find . -name "sikep434r2_fp_x64_asm.S")
	SIKEP434R2_ASM_TEST_OUT := "test_sikep434r2_fp_x64_asm.o"
	TRY_COMPILE_SIKEP434R2_ASM := $(shell $(CC) -c -o $(SIKEP434R2_ASM_TEST_OUT) $(SIKEP434R2_ASM_SRC) > /dev/null 2>&1; echo $$?; rm $(SIKEP434R2_ASM_TEST_OUT) > /dev/null 2>&1)
	ifeq ($(TRY_COMPILE_SIKEP434R2_ASM), 0)
		CFLAGS += -DS2N_SIKEP434R2_ASM
		CFLAGS_LLVM += -DS2N_SIKEP434R2_ASM

		# The ADX instruction set is preferred for best performance, but not necessary.
		TRY_COMPILE_SIKEP434R2_ASM_ADX := $(shell $(CC) -DS2N_ADX -c -o $(SIKEP434R2_ASM_TEST_OUT) $(SIKEP434R2_ASM_SRC) > /dev/null 2>&1; echo $$?; rm $(SIKEP434R2_ASM_TEST_OUT) > /dev/null 2>&1)
		ifeq ($(TRY_COMPILE_SIKEP434R2_ASM_ADX), 0)
			CFLAGS += -DS2N_ADX
			ASFLAGS += -DS2N_ADX
		endif

		SIKEP434R2_ASM_OBJ=$(SIKEP434R2_ASM_SRC:.S=.o)
	endif
endif
