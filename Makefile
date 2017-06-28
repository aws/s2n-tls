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

PLATFORM := $(shell uname)
MAKEFLAGS += PLATFORM=$(PLATFORM)

ifndef LIBCRYPTO_ROOT
	export LIBCRYPTO_ROOT = $(shell echo "`pwd`/libcrypto-root")
endif

DIRS=$(wildcard */)
SRCS=$(wildcard *.c)
OBJS=$(SRCS:.c=.o)

.PHONY : all
all: bin
	$(MAKE) -C tests

bitcode :
	${MAKE} -C tests/saw bitcode

.PHONY : bc
bc: 
	${MAKE} -C crypto bc
#	${MAKE} -C stuffer bc
	${MAKE} -C tls bc
#	${MAKE} -C utils bc

.PHONY : saw
saw : bc 
	$(MAKE) -C tests/saw

include s2n.mk

.PHONY : libs
libs:
	$(MAKE) -C utils
	$(MAKE) -C error
	$(MAKE) -C stuffer
	$(MAKE) -C crypto
	$(MAKE) -C tls
	$(MAKE) -C lib

.PHONY : bin
bin: libs
	$(MAKE) -C bin
	$(MAKE) -C utils
	$(MAKE) -C error
	$(MAKE) -C stuffer
	$(MAKE) -C crypto
	$(MAKE) -C tls
	$(MAKE) -C lib

.PHONY : integration
integration: bin
	$(MAKE) -C tests integration


.PHONY : fuzz
ifeq ($(shell uname),Linux)
fuzz : fuzz-linux
else
fuzz : fuzz-osx
endif

.PHONY : fuzz-osx
fuzz-osx : 
	@echo "\033[33;1mSKIPPED\033[0m Fuzzing is not supported on \"$$(uname -mprs)\" at this time."

.PHONY : fuzz-linux
fuzz-linux : export S2N_UNSAFE_FUZZING_MODE = 1
fuzz-linux : bin
	$(MAKE) -C tests fuzz

.PHONY : indent
indent:
	$(MAKE) -C tests indentsource
	$(MAKE) -C stuffer indentsource
	$(MAKE) -C crypto indentsource
	$(MAKE) -C utils indentsource
	$(MAKE) -C error indentsource
	$(MAKE) -C tls indentsource
	$(MAKE) -C bin indentsource

.PHONY : pre_commit_check
pre_commit_check: all indent clean

.PHONY : clean
clean:
	$(MAKE) -C tests clean
	$(MAKE) -C stuffer decruft
	$(MAKE) -C crypto decruft
	$(MAKE) -C utils decruft
	$(MAKE) -C error decruft
	$(MAKE) -C tls decruft
	$(MAKE) -C bin decruft
	$(MAKE) -C lib decruft
