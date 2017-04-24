#####################
# Copyright 2016 Galois, Inc. All Rights Reserved
#
#  Authors:
#	Joey Dodds : jdodds@galois.com
#       Nathan Collins : conathan@galois.com
#	
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
########################

SCRIPTS = $(wildcard *.saw)
#A log file will be created for each test in the temp dir
LOGS=$(patsubst %.saw,tmp/%.log,$(SCRIPTS))
SHELL:=/bin/bash
Z3_VERSION=$(shell z3 --version)
export LIBCRYPTO_ROOT:=$(shell pwd)/../../libcrypto-root

.PHONY : all
all:
	@echo "Running formal verification with ${Z3_VERSION}"
	@${MAKE} clean-logs
	@${MAKE} $(LOGS)
	@${MAKE} failure-tests

.PHONY : clean-logs
clean-logs : 
	$(RM) -- $(wildcard tmp/*.log)

.PHONY : clean-bitcode
clean-bitcode :
	$(RM) -- bitcode/all_llvm.bc

.PHONY : clean-failure-logs
clean-failure-logs :
	$(RM) -- $(wildcard failure_tests/*.log)


tmp/%.log : %.saw bitcode/all_llvm.bc tmp
	@echo "Running formal verification with ${Z3_VERSION}"
	@echo saw $<
	@set -o pipefail; \
	saw $< | tee $@

.PHONY: clean
clean: decruft

.PHONY: decruft
decruft : clean-logs
	${MAKE} -C bitcode decruft
	${RM} -r s2n
	${RM} -r tmp


FAILURE_PATCHES = $(wildcard failure_tests/*.patch)
FAILURE_LOGS = $(FAILURE_PATCHES:.patch=.log)

.PHONY : failure-tests
failure-tests : bitcode
	@${MAKE} clean-failure-logs
	@${MAKE} failure_tests/bad_magic_mod.log
	@${MAKE} failure_tests/msgchange.log

#@${MAKE} $(FAILURE_LOGS) commented for now because these can't happen in parallel

#The bitcode files don't get deleted, in case we want to do tests on them
.SECONDARY : $(wildcard btcode/*.bc)

failure_tests/%.log : bitcode/%.bc
	cp $< bitcode/all_llvm.bc
	! saw verify_s2n_hmac_sha256.saw &> $@

#keeping track of the status to make sure that even if the make fails the patch still gets undone
bitcode/%.bc : failure_tests/%.patch
	patch -p1 -d s2n -i ../$<
	${MAKE} -C s2n bc; \
        status=$$?; \
	cp bitcode/all_llvm.bc $@
	patch -R -p1 -d s2n -i  ../$<; \
        exit $$status

#if we ask this makefile to create bitcode it will always completely rebuild it
.PHONY : bitcode
bitcode :
	${MAKE} clean_the_dir
	${MAKE} bitcode/all_llvm.bc

clean_the_dir :
	${RM} -r s2n
	${RM} -r tmp
	${RM} -r failure_tests/*.log
	${RM} -r bitcode/*.bc

CRYPTO_C = $(wildcard ../../crypto/*.c) $(wildcard ../../crypto/*.h) ../../crypto/Makefile
CRYPTO_COPY = $(addprefix s2n/crypto/, $(notdir $(CRYPTO_C)))

UTILS_COPY =$(addprefix s2n/utils/, $(notdir $(wildcard ../../utils/*.h)))
TLS_COPY =$(addprefix s2n/tls/, $(notdir $(wildcard ../../tls/*.h)))
STUFFER_COPY =$(addprefix s2n/stuffer/, $(notdir $(wildcard ../../stuffer/*.h)))
API_COPY =$(addprefix s2n/api/, $(notdir $(wildcard ../../api/*.h)))
ERROR_COPY =$(addprefix s2n/error/, $(notdir $(wildcard ../../error/*.h)))

s2n/error :
	mkdir -p $@

s2n/api :
	mkdir -p $@

s2n/crypto :
	mkdir -p $@

s2n/utils :
	mkdir -p $@

s2n/tls :
	mkdir -p $@

s2n/stuffer :
	mkdir -p $@

export BITCODE_DIR := $(CURDIR)/bitcode/

tmp:
	mkdir -p tmp

tmp/IS_PATCHED : | tmp
	if [ -f ../patch.patch ]; then patch -p1 -d s2n -i ../patch.patch; fi
	touch $@

bitcode/all_llvm.bc : s2n/crypto s2n/utils s2n/stuffer s2n/tls s2n/api s2n/error s2n/Makefile s2n/s2n.mk $(CRYPTO_COPY) $(UTILS_COPY) $(TLS_COPY) $(STUFFER_COPY) $(API_COPY) $(ERROR_COPY)
	${MAKE} -C s2n bc

s2n/%.h : ../../%.h
	cp $< $@

s2n/%.c : ../../%.c
	cp $< $@

s2n/%Makefile : ../../%Makefile
	cp $< $@

s2n/Makefile : ../../Makefile
	cp $< $@

s2n/s2n.mk : ../../s2n.mk
	cp $< $@




