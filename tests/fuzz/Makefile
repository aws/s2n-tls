#
# Copyright 2016 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

CRUFT += $(wildcard *_test) $(wildcard fuzz-*.log) $(wildcard *_test_output.txt) $(wildcard *_test_results.txt) $(wildcard LD_PRELOAD/*.so)
LIBS += -lm -ltests2n

CFLAGS += -Wno-unreachable-code -O0 -I$(LIBCRYPTO_ROOT)/include/ -I../
LDFLAGS += $(LIBFUZZER_ROOT)/lib/libFuzzer.a -lstdc++ -L../../lib/ ${CRYPTO_LDFLAGS} -L../testlib/ -ls2n ${LIBS} ${CRYPTO_LIBS} -L../testlib/

DYLD_LIBRARY_PATH="../../lib/:../testlib/:$(LIBCRYPTO_ROOT)/lib:$$DYLD_LIBRARY_PATH"
LD_LIBRARY_PATH="../../lib/:../testlib/:$(LIBCRYPTO_ROOT)/lib:$$LD_LIBRARY_PATH"

ld-preload :
	${MAKE} -C LD_PRELOAD

$(TESTS)::
	@${CC} ${CFLAGS} $@.c -o $@  ${LDFLAGS} > /dev/null

run_tests:: $(TESTS) ld-preload
	@( fail_count=0; for test_name in ${FUZZ_TESTS} ; do \
	export LD_LIBRARY_PATH=${LD_LIBRARY_PATH}; \
	export DYLD_LIBRARY_PATH=${DYLD_LIBRARY_PATH}; \
	export LIBCRYPTO_ROOT=${LIBCRYPTO_ROOT}; \
	./runFuzzTest.sh $${test_name} ${FUZZ_TIMEOUT_SEC} || fail_count=`expr $$fail_count + 1`; done; \
	exit $${fail_count}; \
	)

.PHONY : clean
clean: decruft
	${MAKE} -C LD_PRELOAD decruft
