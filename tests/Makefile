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

OPENSSL_VERSION=$(shell $(LIBCRYPTO_ROOT)/bin/openssl version 2> /dev/null || echo 1)
ifeq (${OPENSSL_VERSION}, 1)
	COMPILE_INFO=Compiled with the missing version of openssl
else
	COMPILE_INFO=Compiled with ${OPENSSL_VERSION}.
endif

.PHONY : all
all: libs viz
	${MAKE} -C unit
	@echo "\033[1m ${COMPILE_INFO} \033[0;39m"

.PHONY : valgrind
valgrind: libs
	${MAKE} -C unit valgrind

.PHONY : libs
libs:
	${MAKE} -C testlib
	${MAKE} -C LD_PRELOAD

.PHONY : integration
integration:
	${MAKE} -C integration

.PHONY : fuzz
fuzz:
	${MAKE} -C testlib
	${MAKE} -C fuzz

.PHONY : viz
viz:
	${MAKE} -C viz

include ../s2n.mk

.PHONY : clean
clean: decruft
	${MAKE} -C testlib decruft
	${MAKE} -C LD_PRELOAD decruft
	${MAKE} -C unit clean
	${MAKE} -C fuzz clean
	${MAKE} -C viz clean
	${MAKE} -C saw decruft

