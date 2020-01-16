include ../../../s2n.mk

BCS=$(wildcard *.bc)

all_llvm.bc : $(BCS)
	$(LLVMLINK) -o $@ $+

bike_r1_llvm.bc : $(BCS)
	$(LLVMLINK) -o $@ $+
