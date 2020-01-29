We verified the C implementation of the BIKE algorithm using the SAW tool and Cryptol language. We verified the operational behaviour of the code, guaranteeing the absence of program errors. For some functions we have additional simplifying assumptions, for example bounding the size of inputs or iterations in a loop. 

## Organization
| # | BIKE file  |    SAW Proof |
| -----: | -----: |------------- | 
| 1 | aes_ctr_prf.c,aes.h | AES.saw
| 2 | bike_r1_kem.c  |  bike_r1_kem.saw, bike_r1_kem_short.saw
| 3 | converts_portable.c | converts_portable.saw
| 4 | decode.c | decode.saw, decode_short.saw
| 5 | openssl_utils.c |  openssl_utils.saw
| 6 | parallel_hash.c | parallel_hash.saw, parallel_hash_short.saw";
| 7 | sampling.c, sampling_portable.c | sampling.saw, sampling_short.saw
| 8 | secure_decode_portable.c | secure_decode_portable.saw
| 9 | utilities.c |  utilities.saw
| 10 | gf2x.h |  gf2x.saw
| 11 | sha.h, sha384.h |  sha.saw

## Verification Effort

The aim of the BIKE verification project is to verify the absence of LLVM undefined behaviours in s2n BIKE.  BIKE includes 44 core functions, by which we mean non OpenSSL / AES functions. Of these 37 were successfully verified and 7 were omitted from verification due to restrictions in our analysis tools.  
The 37 successfully verified functions include: 
- a mix of top, middle, and low-level functions. 
- the 6 top-level KEM functions (`crypto_kem_dec`, `crypto_kem_enc`,  `crypto_kem_keypair`,  `encrypt`,` calc_pk`,  `get_ss`). 
- all functions defined in the decapsulation path, aside from decode. 
-  27 functions are verified with a full-size input parameter set and 10 use the reduced input parameter sizes. 

The omitted functions include: 
- 4 BIKE functions could not be fully verified because they use features not supported by our toolchain. These functions are small in scale, and we recommend careful audit to ensure absence of memory errors. 
- 3 BIKE functions caused our verification tools to time out for some input sizes (`decode`, `compute_counter_of_unsat`, `count_ones`). We were able to verify decode under simplifying assumptions that we believe to be sound. We will revisit these functions in Phase 2 of the project when we lift limits on parameter sizes. 
-  BIKE includes 16 wrapped calls to OpenSSL for algebraic work, basic AES encryption, and hashing with SHA. Verifying OpenSSL code was out of scope and we therefore considered these functions low priority. Nonetheless we verified 4 of them as part of the project (`finalize_aes_ctr_prf`,  `init_aes_ctr_prf_state`, `ossl_add`,  `perform_aes`). 




  
