#
# Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

BCS_11=pq_random.bc
BCS1=$(addprefix $(BITCODE_DIR), $(BCS_11))

.PHONY : all
all: $(OBJS)
	$(MAKE) -C sike

.PHONY : bc
bc: $(BCS1)
	$(MAKE) -C sike bc

.PHONY : run-gcov
run-gcov: gcov
	$(MAKE) -C sike gcov

.PHONY : run-lcov
run-lcov: lcov
	$(MAKE) -C sike lcov

.PHONY : clean
clean: decruft
	${MAKE} -C sike decruft

include ../s2n.mk
