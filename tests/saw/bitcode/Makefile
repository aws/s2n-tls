include ../../../s2n.mk

BCS=$(wildcard *.bc)

%_llvm.bc: $(BCS)
	$(LLVMLINK) -o $@ $+

