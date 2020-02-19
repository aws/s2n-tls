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
OVERRIDES=$(SRCS:.c=)

.PHONY : all
all : $(OVERRIDES)

include ../../../s2n.mk

CRUFT += $(wildcard *.so)

LD_PRELOAD_CFLAGS = -Wno-unreachable-code -O0 -I$(LIBCRYPTO_ROOT)/include/ -I../../../ -I../../../api/

$(OVERRIDES)::
	# Don't include Sanitizer/Fuzz compiler flags since when the LD_PRELOAD shared object is Preloaded, the Sanitizer init 
	# functions won't have been loaded yet, causing undefined symbol errors.
	${CC} ${DEFAULT_CFLAGS} ${DEBUG_CFLAGS} ${LD_PRELOAD_CFLAGS} -shared -fPIC $@.c -o $@.so -ldl
