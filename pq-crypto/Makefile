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
	$(MAKE) -C kyber_r3
endif

.PHONY : run-lcov
run-lcov: lcov
	$(MAKE) -C kyber_r3 lcov

.PHONY : clean
clean: decruft
	$(MAKE) -C kyber_r3 decruft

include ../s2n.mk
