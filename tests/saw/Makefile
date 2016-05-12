SCRIPTS = $(wildcard *.saw)
LOGS=$(SCRIPTS:.saw=.log)

PATCH_FILE = distinguish_update_calls_at_different_sizes.patch

.PHONY : all
all: clean-logs $(LOGS)

bitcode :
	patch -p2  -i $(PATCH); \

clean-logs : 
	$(RM) -- *.log


%.log : %.saw
	./saw $< | tee $@

runsaw :
	$(foreach script,$(SCRIPTS),./saw $(script) && )echo

decruft :
	${MAKE} -C bitcode decruft


