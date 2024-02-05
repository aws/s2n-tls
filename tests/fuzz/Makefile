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
CRYPTO_LDFLAGS = -L$(LIBCRYPTO_ROOT)/lib
SHELL:=/bin/bash


ifndef LIBFUZZER_ROOT
    export LIBFUZZER_ROOT = $(shell echo "../../fuzz_dependencies")
endif

ifndef FUZZ_TIMEOUT_SEC
    export FUZZ_TIMEOUT_SEC=120
endif

ifndef FUZZ_TESTS
    export FUZZ_TESTS=${TESTS}
endif

.PHONY : all
all : run_tests

include ../../s2n.mk

CRUFT += $(wildcard *_test) $(wildcard fuzz-*.log) $(wildcard *_test_output.txt) $(wildcard *_test_results.txt) $(wildcard LD_PRELOAD/*.so) $(wildcard *.prof*)

# We do not warn on unused results (-Wno-unused-result) because we expect that 
# many of the fuzz test inputs will not be valid and operations will not succeed.
CFLAGS += -Wno-unreachable-code -Wno-unused-result -O0 -I$(LIBCRYPTO_ROOT)/include/ -I../
LIBS += -L../testlib/ -ltests2n -L../../lib/ -ls2n
LDFLAGS += $(LIBFUZZER_ROOT)/lib/libFuzzer.a -lstdc++
LDFLAGS += ${CRYPTO_LDFLAGS} ${LIBS} ${CRYPTO_LIBS} -lm -ldl -lrt -pthread

DYLD_LIBRARY_PATH="../../lib/:../testlib/:$(LIBCRYPTO_ROOT)/lib:$$DYLD_LIBRARY_PATH"
LD_LIBRARY_PATH="../../lib/:../testlib/:$(LIBCRYPTO_ROOT)/lib:$$LD_LIBRARY_PATH"

ifdef AFL_FUZZ
    ifneq ($(FUZZ_COVERAGE), true)
        CFLAGS += $(LIBFUZZER_ROOT)/FuzzingEngine.a
    endif
endif


ld-preload :
	${MAKE} -C LD_PRELOAD

$(TESTS)::
	@${CC} ${CFLAGS} $@.c -o $@  ${LDFLAGS}

run_tests:: $(FUZZ_TESTS) ld-preload
	{ set -e; \
	for test_name in ${FUZZ_TESTS} ; do \
	export LD_LIBRARY_PATH=${LD_LIBRARY_PATH}; \
	export DYLD_LIBRARY_PATH=${DYLD_LIBRARY_PATH}; \
	export LIBCRYPTO_ROOT=${LIBCRYPTO_ROOT}; \
	./runFuzzTest.sh $${test_name} ${FUZZ_TIMEOUT_SEC}; done; \
	}
	./calcTotalCov.sh

.PHONY : clean
clean: decruft
	${MAKE} -C LD_PRELOAD decruft
	rm -rf profiles
