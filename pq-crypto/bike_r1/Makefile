# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0"

.DEFAULT_GOAL := all

include ../../s2n.mk

SRCS=$(wildcard *.c)
OBJS=$(SRCS:.c=.o)

#WA for GCC 4.8.5 bug.
CFLAGS += -Wno-missing-braces -Wno-missing-field-initializers -I../../

.PHONY : all
all: $(OBJS)

CFLAGS_LLVM = -emit-llvm -c -g \
              -std=c99 -fgnu89-inline -D_POSIX_C_SOURCE=200809L -D_FORTIFY_SOURCE=2 \
              -I$(LIBCRYPTO_ROOT)/include/ -I../../api/ -I../../

BCS=$(addprefix $(BITCODE_DIR), $(SRCS:.c=.bc))

.PHONY : bc
bc: $(BCS)
