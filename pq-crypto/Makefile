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
SRCS=$(wildcard *.c)
OBJS=$(SRCS:.c=.o)

BCS_11=s2n_pq_random.bc s2n_pq.bc
BCS1=$(addprefix $(BITCODE_DIR), $(BCS_11))

ifdef S2N_NO_PQ
# If S2N_NO_PQ is defined, we build only the top-level pq-crypto directory, and exclude all the PQ crypto code
S2N_NO_PQ_ASM = 1
.PHONY : all
all: $(OBJS)
else
# Explicitly specify `try_include_asm` target for KEMs that attempt to include assembly
.PHONY : all
all: $(OBJS)
	$(MAKE) -C bike_r1
	$(MAKE) -C bike_r2
	$(MAKE) -C bike_r3
	$(MAKE) -C sike_r1
	$(MAKE) -C sike_r2 try_include_asm
	$(MAKE) -C kyber_r2
	$(MAKE) -C kyber_90s_r2
	$(MAKE) -C kyber_r3
	$(MAKE) -C sike_r3
endif

.PHONY : sike_r1_bc
sike_r1_bc: $(BCS1)
	$(MAKE) -C sike_r1 bc

.PHONY : sike_r2_bc
sike_r2_bc: $(BCS1)
	$(MAKE) -C sike_r2 bc

.PHONY : bike_r1_bc
bike_r1_bc: $(BCS1)
	$(MAKE) -C bike_r1 bc

.PHONY : bike_r2_bc
bike_r2_bc: $(BCS1)
	$(MAKE) -C bike_r2 bc

.PHONY : run-gcov
run-gcov: gcov
	$(MAKE) -C sike_r1 gcov
	$(MAKE) -C sike_r2 gcov

.PHONY : run-lcov
run-lcov: lcov
	$(MAKE) -C sike_r1 lcov
	$(MAKE) -C sike_r2 lcov

.PHONY : clean
clean: decruft
	$(MAKE) -C bike_r1 decruft
	$(MAKE) -C bike_r2 decruft
	$(MAKE) -C bike_r3 decruft
	$(MAKE) -C sike_r1 decruft
	$(MAKE) -C sike_r2 decruft
	$(MAKE) -C kyber_r2 decruft
	$(MAKE) -C kyber_90s_r2 decruft
	$(MAKE) -C kyber_r3 decruft
	$(MAKE) -C sike_r3 decruft

include ../s2n.mk
include ./s2n_pq_asm.mk
