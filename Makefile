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

PLATFORM := $(shell uname)
MAKEFLAGS += PLATFORM=$(PLATFORM)

ifndef LIBCRYPTO_ROOT
	export LIBCRYPTO_ROOT = $(shell echo "`pwd`/libcrypto-root")
endif

export S2N_ROOT=$(shell pwd)
export COVERAGE_DIR = $(shell echo "${S2N_ROOT}/coverage")
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
	${MAKE} -C stuffer bc
	${MAKE} -C tls bc
	${MAKE} -C utils bc

.PHONY : sike_r1_bc
sike_r1_bc: bc
	${MAKE} -C pq-crypto sike_r1_bc

.PHONY : sike_r2_bc
sike_r2_bc: bc
	${MAKE} -C pq-crypto sike_r2_bc

.PHONY : bike_r1_bc
bike_r1_bc: bc
	${MAKE} -C pq-crypto bike_r1_bc

.PHONY : bike_r2_bc
bike_r2_bc: bc
	${MAKE} -C pq-crypto bike_r2_bc

.PHONY : saw
saw : bc
	$(MAKE) -C tests/saw

include s2n.mk

.PHONY : libs
libs:
	$(MAKE) -C pq-crypto
	$(MAKE) -C utils
	$(MAKE) -C error
	$(MAKE) -C stuffer
	$(MAKE) -C crypto
	$(MAKE) -C tls
	$(MAKE) -C lib

.PHONY : bin
bin: libs
	$(MAKE) -C bin

.PHONY : integration
integration: bin
	$(MAKE) -C tests integration

.PHONY : integrationv2
integrationv2: bin
	$(MAKE) -C tests integrationv2

.PHONY : valgrind
valgrind: bin
	$(MAKE) -C tests valgrind

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

.PHONY : benchmark
benchmark: bin
	$(MAKE) -C tests benchmark

.PHONY : coverage
coverage: run-gcov run-lcov run-genhtml

.PHONY : run-gcov
run-gcov:
	$(MAKE) -C bin gcov
	$(MAKE) -C crypto gcov
	$(MAKE) -C error gcov
	$(MAKE) -C pq-crypto run-gcov
	$(MAKE) -C stuffer gcov
	$(MAKE) -C tests gcov
	$(MAKE) -C tls run-gcov
	$(MAKE) -C utils gcov

.PHONY : run-lcov
run-lcov:
	$(MAKE) -C bin lcov
	$(MAKE) -C crypto lcov
	$(MAKE) -C error lcov
	$(MAKE) -C pq-crypto run-lcov
	$(MAKE) -C stuffer lcov
	$(MAKE) -C tests lcov
	$(MAKE) -C tls run-lcov
	$(MAKE) -C utils lcov
	lcov -a crypto/coverage.info -a error/coverage.info -a pq-crypto/coverage.info -a pq-crypto/sike_r1/coverage.info -a pq-crypto/sike_r2/coverage.info -a stuffer/coverage.info -a tls/coverage.info -a $(wildcard tls/*/coverage.info) -a utils/coverage.info --output ${COVERAGE_DIR}/all_coverage.info

.PHONY : run-genhtml
run-genhtml:
	genhtml -o ${COVERAGE_DIR}/html ${COVERAGE_DIR}/all_coverage.info


.PHONY : indent
indent:
	$(MAKE) -C pq-crypto indentsource
	$(MAKE) -C tests indentsource
	$(MAKE) -C stuffer indentsource
	$(MAKE) -C crypto indentsource
	$(MAKE) -C utils indentsource
	$(MAKE) -C error indentsource
	$(MAKE) -C tls indent
	$(MAKE) -C bin indentsource

.PHONY : pre_commit_check
pre_commit_check: all indent clean

# TODO use awslabs instead
DEV_IMAGE ?= camshaft/s2n-dev
DEV_OPENSSL_VERSION ?= openssl-1.1.1
DEV_VERSION ?= ubuntu_18.04_$(DEV_OPENSSL_VERSION)_gcc9

dev:
	@docker run -it --rm --ulimit memlock=-1 -v `pwd`:/home/s2n-dev/s2n $(DEV_IMAGE):$(DEV_VERSION)

.PHONY : clean
clean:
	$(MAKE) -C pq-crypto clean
	$(MAKE) -C tests clean
	$(MAKE) -C stuffer decruft
	$(MAKE) -C crypto decruft
	$(MAKE) -C utils decruft
	$(MAKE) -C error decruft
	$(MAKE) -C tls clean
	$(MAKE) -C bin decruft
	$(MAKE) -C lib decruft
	$(MAKE) -C coverage clean
