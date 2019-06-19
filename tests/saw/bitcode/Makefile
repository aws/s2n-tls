include ../../../s2n.mk

BCS=$(wildcard *.bc)

all_llvm.bc : $(BCS)
	$(LLVMLINK) -o $@ $+

all_llvm_patched.bc : $(BCS)
	$(LLVMLINK) -o $@ $+
