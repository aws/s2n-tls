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

all: $(OBJS) run_tests

include ../../s2n.mk

CRUFT += $(wildcard *_test)

# Suppress the unreachable code warning, because tests involve what should be
# unreachable code
CFLAGS += -Wno-unreachable-code -I../../ -I../../api/
LDFLAGS += -L../../lib/ -L../testlib/ -ltests2n -ls2n -lcrypto -lpthread -lm

run_tests: build_tests
	(for test in *_test ; do DYLD_LIBRARY_PATH="../../lib/:../testlib/:$$DYLD_LIBRARY_PATH" LD_LIBRARY_PATH="../../lib/:../testlib/:$$LD_LIBRARY_PATH" ./$$test || exit 1 ; done )

build_tests: 
	(for test in *.c; do ${CC} ${CFLAGS} -o `echo $$test | sed 's/.c$$//'` $$test ${LDFLAGS} ; done) 
