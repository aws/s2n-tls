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
CRYPTO_LDFLAGS = -L$(LIBCRYPTO_ROOT)/lib

# Users can specify a subset of tests to be run, otherwise run all tests.
ifeq (,$(strip ${UNIT_TESTS}))
	UNIT_TESTS := ${TESTS}
endif

.PHONY : all
.PRECIOUS : $(TESTS)

all: $(UNIT_TESTS)

include ../../s2n.mk

# Verify that the ASM code compiles before actually including it in the build.
# (At least) One unit test verifies if we are using the PQ ASM code, so we need to
# include the flag here as appropriate.
# Output is directed to /dev/null so it doesn't pollute the console on compilation
# failures that may be expected.
ifndef S2N_NO_PQ_ASM
	TRY_COMPILE_PQ_ASM := $(shell $(CC) -c -o ../../pq-crypto/sike_r2/fp_x64_asm.o ../../pq-crypto/sike_r2/fp_x64_asm.S > /dev/null 2>&1; echo $$?)
	ifneq ($(TRY_COMPILE_PQ_ASM), 0)
		CFLAGS += -DS2N_NO_PQ_ASM
	endif
endif

CRUFT += $(wildcard *_test)
LIBS += -lm -ltests2n -ls2n -ldl

# Suppress the unreachable code warning, because tests involve what should be
# unreachable code
CFLAGS += -Wno-unreachable-code -I../
LDFLAGS += -L../../lib/ ${CRYPTO_LDFLAGS} -L../testlib/ ${LIBS} ${CRYPTO_LIBS}

ifdef S2N_ADDRESS_SANITIZER
$(UNIT_TESTS)::
	@${CC} ${CFLAGS} -o $@ $@.c ${LDFLAGS} 2>&1
	@DYLD_LIBRARY_PATH="../../lib/:../testlib/:$(LIBCRYPTO_ROOT)/lib:$$DYLD_LIBRARY_PATH" \
	LD_LIBRARY_PATH="../../lib/:../testlib/:$(LIBCRYPTO_ROOT)/lib:$$LD_LIBRARY_PATH" \
	./$@
else
$(UNIT_TESTS)::
	@${CC} ${CFLAGS} -o $@ $@.c ${LDFLAGS} 2>&1
	@DYLD_LIBRARY_PATH="../../lib/:../testlib/:$(LIBCRYPTO_ROOT)/lib:$$DYLD_LIBRARY_PATH" \
	LD_LIBRARY_PATH="../../lib/:../testlib/:$(LIBCRYPTO_ROOT)/lib:$$LD_LIBRARY_PATH" \
	LD_PRELOAD="../LD_PRELOAD/allocator_overrides.so" \
	./$@
endif

$(VALGRIND_TESTS)::
	@${CC} ${CFLAGS} -o $(@:.valgrind=) $(@:.valgrind=.c) ${LDFLAGS} 2>&1
	@DYLD_LIBRARY_PATH="../../lib/:../testlib/:$(LIBCRYPTO_ROOT)/lib:$$DYLD_LIBRARY_PATH" \
	LD_LIBRARY_PATH="../../lib/:../testlib/:$(LIBCRYPTO_ROOT)/lib:$$LD_LIBRARY_PATH" \
	S2N_VALGRIND=1 \
	valgrind --leak-check=full --run-libc-freeres=no -q --error-exitcode=9 --gen-suppressions=all --log-fd=2 --num-callers=40 --leak-resolution=high --undef-value-errors=no --trace-children=yes --suppressions=valgrind.suppressions \
	./$(@:.valgrind=)

.PHONY : valgrind
valgrind: $(VALGRIND_TESTS)


.PHONY : clean
clean: decruft
	@$(foreach test, $(TESTS), rm -f -- "${test}";)

