SCRIPTS = $(wildcard *.saw)
LOGS=$(SCRIPTS:.saw=.log)
SHELL:=/bin/bash 

PATCH_FILE = distinguish_update_calls_at_different_sizes.patch

.PHONY : all
all:
	@${MAKE} clean-logs
	@${MAKE} $(LOGS)

.PHONY : clean-logs
clean-logs : 
	$(RM) -- $(wildcard *.log)


%.log : %.saw
	@echo saw $<
	@set -o pipefail; \
	./saw $< | tee $@


decruft : clean-logs
	${MAKE} -C bitcode decruft
	${RM} -r s2n
	${RM} IS_PATCHED


###############
#The following is to allow for patching s2n during development
#to use it, put a patch (at the level of the s2n directory) in the file
#patch.patch in this directory and call the bitcode target. That will
#create bitcode/all_llvm.bc, which can be used by SAW

#beware: the copied directory gets deleted every time that tests are run, so modifications
#should not be made there
################

bitcode : clean_the_dir bitcode/all_llvm.bc

clean_the_dir :
	${RM} -r s2n
	${RM} -r IS_PATCHED

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

IS_PATCHED :
	patch -p1 -d s2n -i ../patch.patch
	touch $@

bitcode/all_llvm.bc : s2n/crypto s2n/utils s2n/stuffer s2n/tls s2n/api s2n/error s2n/Makefile s2n/s2n.mk $(CRYPTO_COPY) $(UTILS_COPY) $(TLS_COPY) $(STUFFER_COPY) $(API_COPY) $(ERROR_COPY) IS_PATCHED
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




