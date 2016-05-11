SCRIPTS = $(wildcard *.saw)

.PHONY : all
all: runsaw

runsaw :
	$(foreach script,$(SCRIPTS),./saw $(script) && )echo

decruft :
	${MAKE} -C bitcode decruft


