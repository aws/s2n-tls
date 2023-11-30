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

#The scripts are all of the saw files in this directory
SCRIPTS = $(wildcard *.saw)
#A log file will be created for each test in the temp dir
LOGS=$(patsubst %.saw,tmp/%.log,$(SCRIPTS))
SHELL:=/bin/bash
YICES_VERSION=$(shell yices-smt2 --version)
export LIBCRYPTO_ROOT:=$(shell pwd)/../../libcrypto-root

.PHONY : all
all:
	@echo "Running formal verification with ${YICES_VERSION}"
	@${MAKE} clean-logs
	@${MAKE} clean_the_dir
	@${MAKE} $(LOGS)
	@${MAKE} failure-tests


############################################
## Clean targets
############################################
.PHONY : clean-logs
clean-logs : 
	$(RM) -- $(wildcard tmp/*.log)

.PHONY : clean-bitcode
clean-bitcode :
	$(RM) -- bitcode/all_llvm.bc

.PHONY : clean-failure-logs
clean-failure-logs :
	$(RM) -- $(wildcard failure_tests/*.log)

.PHONY: clean
clean: decruft

.PHONY: decruft
decruft : clean-logs
	${MAKE} -C bitcode decruft
	${RM} -r s2n
	${RM} -r tmp

clean_the_dir :
	${RM} -r s2n
	${RM} -r tmp
	${RM} -r failure_tests/*.log
	${RM} -r bitcode/*.bc

###########################################
## Script Tests
###########################################

# To make a log we need the corresponding saw file, the all_llvm file, and a temp directory
# The pipefail command causes the entire command to fail if saw fails, even though we pipe it to tee
# without it we would see only the tee return code
tmp/%.log : %.saw bitcode/all_llvm.bc tmp
	@echo "Running formal verification with ${YICES_VERSION}"
	@echo "Running formal verification with SAW version:"
	@saw --version
	set -o pipefail; \
	saw $< | tee $@

###########################################
## Failure Tests
##
## where we patch the code and make sure
## that our proofs fail when it is patched
## with errors
###########################################

#These won't work in parallel, so we just hard code them,
#Otherwise we'd have to make a separate patched folder for each one
.PHONY : failure-tests
failure-tests : bitcode
	@${MAKE} clean-failure-logs
	@${MAKE} failure_tests/tls_early_ccs.log
	@${MAKE} failure_tests/tls_missing_full_handshake.log
	@${MAKE} failure_tests/sha_bad_magic_mod.log
	@${MAKE} failure_tests/cork_one.log
	@${MAKE} failure_tests/cork_two.log

#The bitcode files don't get deleted, in case we want to do tests on them
.SECONDARY : $(wildcard bitcode/*.bc)

# We're just making separate prefix targets for each saw script we want to do
# negative tests on
failure_tests/sha_%.log : bitcode/sha_%.bc
        #this might not be necessary
	cp $< bitcode/all_llvm.bc 
	set -o pipefail; \
	! (saw verify_HMAC.saw 2>&1 | tee $@)
	grep "error: in _SAW_verify_prestate" $@

failure_tests/tls_%.log : bitcode/tls_%.bc
        #this might not be necessary
	cp $< bitcode/all_llvm.bc 
	set -o pipefail; \
	! (saw verify_state_machine.saw 2>&1 | tee $@)
	grep "error: in _SAW_verify_prestate" $@

failure_tests/cork_%.log : bitcode/cork_%.bc
        #this might not be necessary
	cp $< bitcode/all_llvm.bc 
	set -o pipefail; \
	! (saw verify_cork_uncork.saw 2>&1 | tee $@)
	grep "error: in llvm_ghost_value" $@


# we patch the s2n dir, build it with the top level s2n makefile, and
# move the resulting, patched and linked llvm bitcode into our bitcode directory
bitcode/%.bc : failure_tests/%.patch
	patch -p1 -d s2n -i ../$<
	${MAKE} -C s2n bc; \
	${MAKE} bitcode/all_llvm.bc; \
        status=$$?; \
	cp bitcode/all_llvm.bc $@
	patch -R -p1 -d s2n -i  ../$<; \
        exit $$status

#if we ask this makefile to create bitcode it will always completely rebuild it
.PHONY : bitcode
bitcode :
	${MAKE} clean_the_dir
	${MAKE} bitcode/all_llvm.bc

########################################################
## Rules to copy the s2n directory for patching and bulding
########################################################

CRYPTO_C = $(wildcard ../../crypto/*.c) $(wildcard ../../crypto/*.h) ../../crypto/Makefile
CRYPTO_COPY = $(addprefix s2n/crypto/, $(notdir $(CRYPTO_C)))

UTILS_C = $(wildcard ../../utils/*.c) $(wildcard ../../utils/*.h) ../../utils/Makefile
UTILS_COPY =$(addprefix s2n/utils/, $(notdir $(UTILS_C)))

TLS_C = $(wildcard ../../tls/*.c ../../tls/*/*.c ../../tls/*.h ../../tls/*/*.h ../../tls/*/Makefile) ../../tls/Makefile
TLS_COPY = $(subst ../../tls/, s2n/tls/, $(TLS_C))
TLS_DIRS = $(sort $(dir $(TLS_COPY)))

STUFFER_C = $(wildcard ../../stuffer/*.c) $(wildcard ../../stuffer/*.h) ../../stuffer/Makefile
STUFFER_COPY =$(addprefix s2n/stuffer/, $(notdir $(STUFFER_C)))

API_COPY = $(subst ../../api, s2n/api, $(wildcard ../../api/*.h ../../api/*/*.h))
API_DIRS = $(sort $(dir $(API_COPY)))

ERROR_C = $(wildcard ../../error/*.c) $(wildcard ../../error/*.h) ../../error/Makefile
ERROR_COPY = $(addprefix s2n/error/, $(notdir $(ERROR_C)))

LIB_COPY = s2n/lib/Makefile

s2n/error :
	mkdir -p $@

s2n/api :
	mkdir -p $(API_DIRS)

s2n/crypto :
	mkdir -p $@

s2n/utils :
	mkdir -p $@

s2n/tls :
	mkdir -p $(TLS_DIRS)

s2n/stuffer :
	mkdir -p $@

s2n/lib :
	mkdir -p $@

export BITCODE_DIR := $(CURDIR)/bitcode/

tmp:
	mkdir -p tmp

bitcode/all_llvm.bc : s2n/crypto s2n/utils s2n/tls s2n/api s2n/error s2n/stuffer s2n/Makefile s2n/s2n.mk $(CRYPTO_COPY) $(PQ_CRYPTO_COPY) $(UTILS_COPY) $(TLS_COPY) $(API_COPY) $(ERROR_COPY) $(STUFFER_COPY)
	${MAKE} -C s2n bc
	${MAKE} -C bitcode all_llvm.bc


s2n/lib/libs2n.so : s2n/crypto s2n/utils s2n/tls s2n/api s2n/error s2n/stuffer s2n/lib s2n/Makefile s2n/s2n.mk $(CRYPTO_COPY) $(UTILS_COPY) $(TLS_COPY) $(API_COPY) $(ERROR_COPY) $(STUFFER_COPY) $(LIB_COPY)
	${MAKE} -C s2n libs NO_STACK_PROTECTOR=1 NO_INLINE=1

s2n/%.h : ../../%.h
	cp $< $@

s2n/%.c : ../../%.c
	cp $< $@

s2n/%.S : ../../%.S
	cp $< $@

s2n/%Makefile : ../../%Makefile
	cp $< $@

s2n/Makefile : ../../Makefile
	cp $< $@

s2n/s2n.mk : ../../s2n.mk
	cp $< $@
