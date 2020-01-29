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
	$(MAKE) -C bike_r1
	$(MAKE) -C bike_r2
	$(MAKE) -C sike_r1
	$(MAKE) -C sike_r2

.PHONY : sike_r1_bc
sike_r1_bc: $(BCS1)
	$(MAKE) -C sike_r1 bc

.PHONY : bike_r1_bc
bike_r1_bc: $(BCS1)
	$(MAKE) -C bike_r1 bc

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
	${MAKE} -C bike_r1 decruft
	$(MAKE) -C bike_r2 decruft
	${MAKE} -C sike_r1 decruft
	${MAKE} -C sike_r2 decruft

include ../s2n.mk
