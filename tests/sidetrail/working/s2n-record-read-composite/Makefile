include ../../lib/ct-verif.mk

cflags +=-D__TIMING_CONTRACTS__
#the overriden .h
cflags += -I$(CURDIR)
#original .h
cflags += -I$(CURDIR)/../../../../
#/api .h that haven't fixed that
cflags += -I$(CURDIR)/../../../../api/
cflags += -fPIC -std=c99 -fgnu89-inline
extras += crypto/s2n_hash.c
extras += crypto/s2n_hmac.c
extras += error/s2n_errno.c
extras += stuffer/s2n_stuffer.c
extras += tls/s2n_record_read_composite.c
extras += utils/s2n_mem.c
extras += utils/s2n_safety.c
goals  += s2n_record_parse_wrapper@s2n_record_read_wrapper.c
#goals += test_leakage@s2n_record_read_wrapper.c
full_self_comp += true
smtlog += p.smt2
shadowingArgs += "self_comp_mode=full,branchcond_assertion=assert_never,memory_assertion=assert_never"
timing += true
printModel += true
