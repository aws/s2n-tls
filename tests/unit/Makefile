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
TESTS=$(SRCS:.c=)
VALGRIND_TESTS=$(SRCS:.c=.valgrind)
PEDANTIC_VALGRIND_TESTS:=$(SRCS:.c=.pedantic_valgrind)
CRYPTO_LDFLAGS = -L$(LIBCRYPTO_ROOT)/lib

# Users can specify a subset of tests to be run, otherwise run all tests.
ifeq (,$(strip ${UNIT_TESTS}))
	UNIT_TESTS := ${TESTS}
endif

.PHONY : all
.PRECIOUS : $(TESTS)

all: $(UNIT_TESTS)

include ../../s2n.mk

CRUFT += $(wildcard *_test)
LIBS += ../testlib/libtests2n.a ../../lib/libs2n.a

# Suppress the unreachable code warning, because tests involve what should be
# unreachable code
CFLAGS += -Wno-unreachable-code -I../
LDFLAGS += ${CRYPTO_LDFLAGS} ${LIBS} ${CRYPTO_LIBS} -lm -ldl

ifdef S2N_ADDRESS_SANITIZER
$(UNIT_TESTS)::
	@${CC} ${CFLAGS} -o $@ $@.c ${LDFLAGS} 2>&1
	@DYLD_LIBRARY_PATH="$(LIBCRYPTO_ROOT)/lib:$$DYLD_LIBRARY_PATH" \
	LD_LIBRARY_PATH="$(LIBCRYPTO_ROOT)/lib:$$LD_LIBRARY_PATH" \
	./$@
else
$(UNIT_TESTS)::
	@${CC} ${CFLAGS} -o $@ $@.c ${LDFLAGS} 2>&1
	@DYLD_LIBRARY_PATH="$(LIBCRYPTO_ROOT)/lib:$$DYLD_LIBRARY_PATH" \
	LD_LIBRARY_PATH="$(LIBCRYPTO_ROOT)/lib:$$LD_LIBRARY_PATH" \
	LD_PRELOAD="../LD_PRELOAD/allocator_overrides.so" \
	./$@
endif

$(VALGRIND_TESTS)::
	@${CC} ${CFLAGS} -o $(@:.valgrind=) $(@:.valgrind=.c) ${LDFLAGS} 2>&1
	@DYLD_LIBRARY_PATH="$(LIBCRYPTO_ROOT)/lib:$$DYLD_LIBRARY_PATH" \
	LD_LIBRARY_PATH="$(LIBCRYPTO_ROOT)/lib:$$LD_LIBRARY_PATH" \
	S2N_VALGRIND=1 \
	valgrind \
		--leak-check=full \
		--leak-resolution=high \
		--trace-children=yes \
		--run-libc-freeres=no \
		-q --error-exitcode=123 \
		--error-limit=no \
		--num-callers=40 \
		--undef-value-errors=no \
		--log-fd=2 \
		--suppressions=valgrind.suppressions \
	./$(@:.valgrind=)

$(PEDANTIC_VALGRIND_TESTS)::
	@${CC} ${CFLAGS} -o $(@:.pedantic_valgrind=) $(@:.pedantic_valgrind=.c) ${LDFLAGS} 2>&1
	@DYLD_LIBRARY_PATH="$(LIBCRYPTO_ROOT)/lib:$$DYLD_LIBRARY_PATH" \
	LD_LIBRARY_PATH="$(LIBCRYPTO_ROOT)/lib:$$LD_LIBRARY_PATH" \
	S2N_VALGRIND=1 \
	valgrind \
		--leak-check=full \
		--leak-resolution=high \
		--trace-children=yes \
		--run-libc-freeres=yes \
		-q --error-exitcode=123 \
		--error-limit=no \
		--num-callers=40 \
		--undef-value-errors=no \
		--show-leak-kinds=all \
		--errors-for-leak-kinds=all \
		--suppressions=valgrind.suppressions \
	./$(@:.pedantic_valgrind=)

.PHONY : valgrind
valgrind: $(VALGRIND_TESTS)

# https://github.com/aws/s2n-tls/issues/3758
# Run valgrind in pedantic mode (--errors-for-leak-kinds=all)
.PHONY : pedantic_valgrind
pedantic_valgrind: $(PEDANTIC_VALGRIND_TESTS)

.PHONY : clean
clean: decruft
	@$(foreach test, $(TESTS), rm -f -- "${test}";)

