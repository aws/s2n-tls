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

SRCS=$(wildcard *.cc)
OBJS=$(SRCS:.c=.o)
TESTS=$(SRCS:.cc=)
CRYPTO_LDFLAGS = -L$(LIBCRYPTO_ROOT)/lib
BENCHMARK_LDFLAGS = -L${GB_INSTALL_DIR}/lib -lbenchmark

# Users can specify a subset of tests to be run, otherwise run all tests.
ifeq (,$(strip ${BM_TESTS}))
	BM_TESTS := ${TESTS}
endif

.PHONY : all
.PRECIOUS : $(TESTS)

all: $(BM_TESTS)

include ../../s2n.mk

CRUFT += $(wildcard *_benchmark)
LIBS += ../testlib/libtests2n.a ../../lib/libs2n.a

# Suppress the unreachable code warning, because tests involve what should be
# unreachable code
CPPFLAGS += -Wno-unreachable-code -I../ -isystem ${GB_INSTALL_DIR}/include -Drestrict=__restrict__
LDFLAGS += ${CRYPTO_LDFLAGS} ${LIBS} ${CRYPTO_LIBS} ${BENCHMARK_LDFLAGS} -lm -ldl -lrt -pthread

$(BM_TESTS)::
	${CXX} ${CPPFLAGS} -o $@ $@.cc ${LDFLAGS} 2>&1
	@DYLD_LIBRARY_PATH="$(LIBCRYPTO_ROOT)/lib:$$DYLD_LIBRARY_PATH" \
	LD_LIBRARY_PATH="$(LIBCRYPTO_ROOT)/lib:$$LD_LIBRARY_PATH" \
	./$@

.PHONY : clean
clean: decruft
	@$(foreach test, $(TESTS), rm -f -- "${test}";)

