#
# Copyright 2014 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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
.DEFAULT_GOAL := all

include ../../s2n.mk

# BIKE version and security level
CFLAGS += -DBIKE1=1 -DPARAM64=1

#WA for GCC 4.8.5 bug.
CFLAGS += -Wno-missing-braces -Wno-missing-field-initializers

# BIKE casts raw char arrays to an internal key representation for safety and convenience in bike1_l1_kem.c
FLAGS_TO_REMOVE := -Wcast-qual -Wstack-protector

ifdef NIST_RNG_FOR_UNIT_TEST
	CFLAGS += -DNIST_RNG_FOR_UNIT_TEST
	LIBRARY_NAME := libbike1_l1_nist_known_answer_rng.so
else
	LIBRARY_NAME := libbike1_l1.so
endif

FINAL_CFLAGS := $(filter-out $(FLAGS_TO_REMOVE),$(CFLAGS))

CFLAGS = $(FINAL_CFLAGS)

SRCS=$(wildcard *.c)
OBJS=$(SRCS:.c=.o)

.PHONY : all
all: libbike1_l1.a

libbike1_l1.a: ${OBJS}
	$(AR) cru libbike1_l1.a ${OBJS}
	$(RANLIB) libbike1_l1.a

.PHONY : clean
clean:
	${MAKE} decruft