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

ifeq ($(PLATFORM),Darwin)
    LIBS = -lc -lpthread
    CRYPTO_LIBS =
else ifeq ($(PLATFORM),FreeBSD)
    LIBS = -lthr
    CRYPTO_LIBS = -lcrypto
else ifeq ($(PLATFORM),NetBSD)
    LIBS = -lpthread
    CRYPTO_LIBS = -lcrypto
else
    LIBS = -lpthread -ldl -lrt
    CRYPTO_LIBS = -lcrypto
endif

CC	= $(CROSS_COMPILE)gcc
AR	= $(CROSS_COMPILE)ar
RANLIB	= $(CROSS_COMPILE)ranlib

SOURCES = $(wildcard *.c *.h)
CRUFT   = $(wildcard *.c~ *.h~ *.c.BAK *.h.BAK *.o *.a *.so *.dylib)
INDENT  = $(shell (if indent --version 2>&1 | grep GNU > /dev/null; then echo indent ; elif gindent --version 2>&1 | grep GNU > /dev/null; then echo gindent; else echo true ; fi ))

DEFAULT_CFLAGS = -pedantic -Wall -Werror -Wimplicit -Wunused -Wcomment -Wchar-subscripts -Wuninitialized \
                 -Wshadow -Wcast-qual -Wcast-align -Wwrite-strings -fPIC \
                 -std=c99 -D_POSIX_C_SOURCE=200809L -O2 -I$(LIBCRYPTO_ROOT)/include/ \
                 -I../api/ -I../ -Wno-deprecated-declarations -Wno-unknown-pragmas -Wformat-security \
                 -D_FORTIFY_SOURCE=2

# Add a flag to disable stack protector for alternative libcs without
# libssp.
ifneq ($(NO_STACK_PROTECTOR), 1)
DEFAULT_CFLAGS += -Wstack-protector -fstack-protector-all
endif

CFLAGS = ${DEFAULT_CFLAGS}

DEBUG_CFLAGS = -g3 -ggdb -fno-omit-frame-pointer -fno-optimize-sibling-calls

FUZZ_CFLAGS = -fsanitize-coverage=edge,trace-cmp -fsanitize=address,undefined,leak

ifeq ($(S2N_UNSAFE_FUZZING_MODE),1)
    # Override compiler to clang if fuzzing, since gcc does not support as many sanitizer flags as clang
    CC=clang

    # Turn on debugging and fuzzing flags when S2N_UNSAFE_FUZZING_MODE is enabled to give detailed stack traces in case
    # an error occurs while fuzzing.
    CFLAGS = ${DEFAULT_CFLAGS} ${DEBUG_FLAGS} ${FUZZ_CFLAGS}
endif

INDENTOPTS = -npro -kr -i4 -ts4 -nut -sob -l180 -ss -ncs -cp1

.PHONY : indentsource
indentsource:
	( for source in ${SOURCES} ; do ${INDENT} ${INDENTOPTS} $$source; done )

.PHONY : decruft
decruft:
	$(RM) -- ${CRUFT}
