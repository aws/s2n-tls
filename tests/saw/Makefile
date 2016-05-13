SCRIPTS = $(wildcard *.saw)
LOGS=$(SCRIPTS:.saw=.log)
SHELL:=/bin/bash 

PATCH_FILE = distinguish_update_calls_at_different_sizes.patch

.PHONY : all
all: clean-logs $(LOGS)

bitcode :
	patch -p2  -i $(PATCH); \

clean-logs : 
	$(RM) -- *.log


%.log : %.saw
	@echo saw $<
	@set -o pipefail; \
	./saw $< | tee $@; 

runsaw :
	$(foreach script,$(SCRIPTS),./saw $(script) && )echo

decruft :
	${MAKE} -C bitcode decruft


