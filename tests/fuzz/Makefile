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

SRCS=$(wildcard *.c)
OBJS=$(SRCS:.c=.o)
TESTS=$(SRCS:.c=)
CRYPTO_LDFLAGS = -L$(LIBCRYPTO_ROOT)/lib

.PHONY : all
all: $(TESTS)

include ../../s2n.mk

CRUFT += $(wildcard *_test) $(wildcard fuzz-*.log) $(wildcard *_test_output.txt)
LIBS += -lm

CFLAGS += -Wno-unreachable-code -O0 -I$(LIBCRYPTO_ROOT)/include/ -I../../ -I../../api/
LDFLAGS += ../../fuzz_dependencies/libFuzzer.a -lstdc++ -L../../lib/ ${CRYPTO_LDFLAGS} -L../testlib/ -ls2n ${LIBS} ${CRYPTO_LIBS}
ASAN_OPTIONS= symbolize=1
LSAN_OPTIONS= log_threads=1
UBSAN_OPTIONS= print_stacktrace=1
FUZZ_TIMEOUT_SEC= 120
LIBFUZZER_ARGS = -timeout=1 -max_len=4096 -use_traces=1 -print_final_stats=1 -jobs=32 -workers=32 \
                   -max_total_time=${FUZZ_TIMEOUT_SEC}

$(TESTS)::
	@${CC} ${CFLAGS} $@.c -o $@ ${LDFLAGS} > /dev/null
	@printf "Running  %-40s for %5d sec... " $@ ${FUZZ_TIMEOUT_SEC}
	@( \
	DYLD_LIBRARY_PATH="../../lib/:../testlib/:$(LIBCRYPTO_ROOT)/lib:$$DYLD_LIBRARY_PATH" \
	LD_LIBRARY_PATH="../../lib/:../testlib/:$(LIBCRYPTO_ROOT)/lib:$$LD_LIBRARY_PATH" \
	ASAN_OPTIONS=${ASAN_OPTIONS} \
	LSAN_OPTIONS=${LSAN_OPTIONS} \
	UBSAN_OPTIONS=${UBSAN_OPTIONS} \
	./$@ ${LIBFUZZER_ARGS} ./corpus/$@ > $@_output.txt 2>&1 \
	|| (echo "\033[31;1mFAILED\033[0m\n"; sleep 2s; cat $@_output.txt; exit -1;) \
	)
	@( \
	printf "\033[32;1mPASSED\033[0m %12d tests, %8d branches covered\n" \
	  `grep -o "stat::number_of_executed_units: [0-9]*" $@_output.txt | awk '{test_count += $$2} END {print test_count}'` \
	  `grep -o "cov: [0-9]*" $@_output.txt | awk '{print $$2}' | sort | tail -1` \
	)

