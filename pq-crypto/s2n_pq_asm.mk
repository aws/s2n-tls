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
TRY_COMPILE_SIKEP434R3_ASM = -1

ifndef S2N_NO_PQ_ASM
	# sikep434r3
	SIKEP434R3_ASM_SRC := $(shell find . -name "sikep434r3_fp_x64_asm.S")
	SIKEP434R3_ASM_TEST_OUT := "test_sikep434r3_fp_x64_asm.o"
	TRY_COMPILE_SIKEP434R3_ASM := $(shell $(CC) -c -o $(SIKEP434R3_ASM_TEST_OUT) $(SIKEP434R3_ASM_SRC) > /dev/null 2>&1; echo $$?; rm $(SIKEP434R3_ASM_TEST_OUT) > /dev/null 2>&1)
	ifeq ($(TRY_COMPILE_SIKEP434R3_ASM), 0)
		CFLAGS += -DS2N_SIKE_P434_R3_ASM
		CFLAGS_LLVM += -DS2N_SIKE_P434_R3_ASM

		# The ADX instruction set is preferred for best performance, but not necessary.
		TRY_COMPILE_SIKEP434R3_ASM_ADX := $(shell $(CC) -DS2N_ADX -c -o $(SIKEP434R3_ASM_TEST_OUT) $(SIKEP434R3_ASM_SRC) > /dev/null 2>&1; echo $$?; rm $(SIKEP434R3_ASM_TEST_OUT) > /dev/null 2>&1)
		ifeq ($(TRY_COMPILE_SIKEP434R3_ASM_ADX), 0)
			CFLAGS += -DS2N_ADX
			ASFLAGS += -DS2N_ADX
		endif

        SIKEP434R3_ASM_OBJ=$(SIKEP434R3_ASM_SRC:.S=.o)
        endif
    
	# BIKE Round-3 code has several different optimizations
	# which require specific compiler flags to be supported
	# by the compiler. So for each needed instruction set
	# extension we check if the compiler supports it and
	# set proper flags to be added in the BIKE_R3 Makefile.
	dummy_file := "$(S2N_ROOT)/tests/features/noop_main.c"
	dummy_file_out := "test_bike_r3_avx_support.o"
	BIKE_R3_AVX2_SUPPORTED := $(shell $(CC) -mavx2 -c -o $(dummy_file_out) $(dummy_file) > /dev/null 2>&1; echo $$?; rm $(dummy_file_out) > /dev/null 2>&1)
	ifeq ($(BIKE_R3_AVX2_SUPPORTED), 0)
		CFLAGS += -DS2N_BIKE_R3_AVX2
		CFLAGS_LLVM += -DS2N_BIKE_R3_AVX2
		BIKE_R3_AVX2_FLAGS := -mavx2
	endif
	BIKE_R3_AVX512_SUPPORTED := $(shell $(CC) -mavx512f -mavx512bw -mavx512dq -c -o $(dummy_file_out) $(dummy_file) > /dev/null 2>&1; echo $$?; rm $(dummy_file_out) > /dev/null 2>&1)
	ifeq ($(BIKE_R3_AVX512_SUPPORTED), 0)
		CFLAGS += -DS2N_BIKE_R3_AVX512
		CFLAGS_LLVM += -DS2N_BIKE_R3_AVX512
		BIKE_R3_AVX512_FLAGS := -mavx512f -mavx512bw -mavx512dq
	endif
	BIKE_R3_PCLMUL_SUPPORTED := $(shell $(CC) -mpclmul -msse2 -c -o $(dummy_file_out) $(dummy_file) > /dev/null 2>&1; echo $$?; rm $(dummy_file_out) > /dev/null 2>&1)
	ifeq ($(BIKE_R3_PCLMUL_SUPPORTED), 0)
		CFLAGS += -DS2N_BIKE_R3_PCLMUL
		CFLAGS_LLVM += -DS2N_BIKE_R3_PCLMUL
		BIKE_R3_PCLMUL_FLAGS := -mpclmul -msse2
	endif
	BIKE_R3_PCLMUL_SUPPORTED := $(shell $(CC) -mvpclmulqdq -c -o $(dummy_file_out) $(dummy_file) > /dev/null 2>&1; echo $$?; rm $(dummy_file_out) > /dev/null 2>&1)
	ifeq ($(BIKE_R3_VPCLMUL_SUPPORTED), 0)
		CFLAGS += -DS2N_BIKE_R3_VPCLMUL
		CFLAGS_LLVM += -DS2N_BIKE_R3_VPCLMUL
		BIKE_R3_VPCLMUL_FLAGS := -mvpclmulqdq -mavx512f -mavx512bw -mavx512dq
	endif
 
    # Kyber Round-3 code has several different optimizations
    # which require specific compiler flags to be supported
    # by the compiler. So for each needed instruction set
    # extension we check if the compiler supports it and
    # set proper flags to be added in the kyber_r3 Makefile.
    dummy_file := "$(S2N_ROOT)/tests/features/noop_main.c"
    dummy_file_out := "test_kyber512r3_avx2_bmi2_support.o"
    KYBER512R3_AVX2_BMI2_SUPPORTED := $(shell $(CC) -mavx2 -mbmi2 -c -o $(dummy_file_out) $(dummy_file) > /dev/null 2>&1; echo $$?; rm $(dummy_file_out) > /dev/null 2>&1)
    ifeq ($(KYBER512R3_AVX2_BMI2_SUPPORTED), 0)
        CFLAGS += -DS2N_KYBER512R3_AVX2_BMI2
        CFLAGS_LLVM += -DS2N_KYBER512R3_AVX2_BMI2
        KYBER512R3_AVX2_BMI2_FLAGS := -mavx2 -mbmi2
    endif
endif
