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
    # Kyber Round-3 code has several different optimizations
    # which require specific compiler flags to be supported
    # by the compiler. So for each needed instruction set
    # extension we check if the compiler supports it and
    # set proper flags to be added in the kyber_r3 Makefile.

    # Check if m256 intrinsics are supported by the compiler
    m256_file := "$(S2N_ROOT)/tests/features/m256_intrinsics.c"
    m256_file_out := "test_kyber512r3_m256_support.o"
    KYBER512R3_M256_SUPPORTED := $(shell $(CC) -c -o $(m256_file_out) $(m256_file) > /dev/null 2>&1; echo $$?; rm $(m256_file_out) > /dev/null 2>&1)

    ifeq ($(KYBER512R3_M256_SUPPORTED), 0)
      # Check if mavx2 and mbmi2 flags are supported by the compiler
      dummy_file := "$(S2N_ROOT)/tests/features/noop_main.c"
      dummy_file_out := "test_kyber512r3_avx2_bmi2_support.o"
      KYBER512R3_AVX2_BMI2_SUPPORTED := $(shell $(CC) -mavx2 -mbmi2 -c -o $(dummy_file_out) $(dummy_file) > /dev/null 2>&1; echo $$?; rm $(dummy_file_out) > /dev/null 2>&1)
    endif
endif
