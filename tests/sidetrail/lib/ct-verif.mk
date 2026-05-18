
# HACK to get the directory of this file
mydir = $(dir $(realpath $(word 2, $(MAKEFILE_LIST))))

entrypoint = $(word 1, $(subst @, ,$1))
sourcefile = $(word 2, $(subst @, ,$1))

ctverif := $(mydir)../bin/ct-verif.rb

# Include the s2n_prelude for macros like S2NMIN/S2NMAX
s2n_root := $(realpath $(mydir)../../..)
cflags_prelude := -include $(s2n_root)/utils/s2n_prelude.h

goals   ?=
unroll	?=
looplim ?=
time	?=
cflags  ?=
extras  ?=
prereqs ?=
secure  ?= true
timing  ?=
printModel ?=
full_self_comp ?=
shadowingArgs ?=

flags = $(strip \
	$(if $(strip $(printModel)),--print-model $(printModel)) \
	$(if $(strip $(full_self_comp)),--full-self-comp $(full_self_comp)) \
	$(if $(strip $(unroll)),--unroll-limit $(unroll)) \
	$(if $(strip $(looplim)),--loop-limit $(looplim)) \
	$(if $(strip $(time)),--time-limit $(time)) \
	$(if $(strip $(timing)),--timing) \
	$(if $(strip $(cflags)),--clang-options="$(cflags_prelude) $(cflags)",--clang-options="$(cflags_prelude)") \
	$(if $(strip $(pruneBefore)),--prune-before) \
	$(if $(strip $(pruneAfter)),--prune-after) \
	$(if $(strip $(shadowingArgs)),--shadowingArgs="$(strip $(shadowingArgs))") \
)

c = compiled.bpl
p = product.bpl
v = verified

.PRECIOUS: %.$(c) %.$(p)
.PHONY: %.$(v) clean

.SECONDEXPANSION:
%.$(c): $$(call sourcefile,$$*) $$(extras) $(prereqs)
	@echo
	@echo Compile | figlet
	@echo $*
	@echo
	@mkdir -p $(dir $@)
	@$(ctverif) $(flags) -a $@ --no-product --no-verify -e $(call entrypoint,$*) $(call sourcefile,$*) $(extras)

%.$(p): %.$(c)
	@echo
	@echo Product | figlet
	@echo $*
	@echo
	@$(ctverif) $(flags) -b $@ --no-compile --no-verify $<

%.$(v): %.$(p)
	@echo
	@echo Verify | figlet
	@echo $*
	@echo
	@$(ctverif) $(flags) --no-compile --no-product $< | tee $*.log
#	@$(secure) || [ -z "$$(grep " 0 errors" $*.log)" ]
#	@not $(secure) || [ -n "$$(grep " 0 errors" $*.log)" ]

all: $$(patsubst %,%.$(v),$$(goals))

clean:
	@echo Removing intermediate files
	@rm -vrf $$(find . -name "*@*")
