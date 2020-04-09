We verified the C implementation of the Supersingular Isogeny Key Encapsulation (SIKE) algorithm using the SAW tool and Cryptol language. Due to the complexity of SIKE, we applied different verification approaches for different portions of the code. These provide varying levels of assurance, i.e. they each rule out specific categories of errors in the code: 

## Approaches 
- Approach 1 (strongest): verification of the mathematical behaviour of the code and the operational behaviour of the code,guaranteeing the absence of program errors.
- Approach 2: verification of the operational behaviour of the code, guaranteeing the absence of program errors. 
- Approach 3 (weakest): verification of operational behaviour with additional simplifying assumptions, for example bounding the size of inputs or iterations in a loop. 
We applied these approaches so as to maximize the assurance we achieved with the time / resources available. We also omitted a very small number of functions as a result of limitations in our verification tools. 

## Organization
###  By mathematical concept and SIKE file


| # | Description | Approach | SIKE file  | Cryptol Specification           | SAW Proof |
| -----: | -----: |------------- | -----: |:-------------:| -----:|
| 1 | Base math operations | 1|config.h | fp_generic.cry  & fpx.cry | word.saw
| 2 | Low-level field operators (fp) | 1 | fp_generic.c     |  fp_generic.cry | field.saw & word.saw |
| 3 | Higher-level field operators (fp2)|1 | fpx.c | fpx.cry  |  field.saw & word.saw |
| 4 |CShake |  1|flips202.c | Keccak.cry | cshake.saw
| 5| Isogeny Functions |  2&3 |ec_isogeny.c | ec_isogeny.cry | curv.saw &  isogeny.saw
| 6| Key generation and encoding | 2&3 |sidh.c | sidh.cry | word.saw & sidh.saw
| 7| SIKE top-level |  2 |sike.c | sike.cry | sike.saw




To be read as, 
1.  We verified  the mathematical behaviour and the operational behaviour of the code (approach 1) that implements base mathematical operations.  Specifically, the functions defined in config.h, are modeleled  in fpx.cry and fp_generic.cry and verified with proofs defined in  word.saw. 
2.  We verified  the mathematical behaviour and the operational behaviour of the code (approach 1) that implements low-level field operators. Specifically, the functions defined in fp_generic.c are modeleled in fp_generic.cry and verified with proofs  defined in field.saw and word.saw. 
3.  We verified  the mathematical behaviour and the operational behaviour of the code (approach 1) that implements low-level field operators.  Specifically, the functions defined in fpx.c, are modeleled  in fpx.cry and verified with proofs defined in field.saw and word.saw. 
4.  We verified  the mathematical behaviour and the operational behaviour of the code (approach 1) that implements CSHAKE operations.  Specifically, the functions defined in flips202.c, are modeleled  in Keccak.cry and verified with proofs defined in cshake.saw. 
5.   We verified the operational behaviour with additional simplifying assumptions, of the code that implements the isogeny functions.    Specifically, the functions defined in ec_isogeny.c, are modeleled  in ec_isogeny.cry and verified with proofs defined in  curv.saw and isogeny.saw.  A handful of functions (`ladder3pt`, `xDBLe`, `xTPLe`) required additional simplifying assumptions (approach 3) due to unbounded loops and large iterations, but the rest of the functions (`get_3_isog`,`xDBLADD`,...) did not require those assumptions (approach 2).
6.   We verified the operational behaviour with additional simplifying assumptions, of the code that implements the key generation and encoding algorithms.    Specifically, the functions defined in sidh.c, are modeleled  in sidh.cry and verified with proofs defined in  word.saw and sidh.saw.  A handful of functions (`EphemeralKeyGeneration_A`, `EphemeralKeyGeneration_B`, `EphemeralSecretAgreement_A`,and `EphemeralSecretAgreement_B`) required additional simplifying assumptions (approach 3) due to unbounded loops and large iterations, but the rest of the functions (`fp2_encode_ov`,`init_basis_ov`,...) did not require those assumptions (approach 2).
 7.   We verified the operational behaviour of the code that implements the top-level SIKE functions.    Specifically, the functions defined in sike.c, are modeleled  in sike.cry and verified with proofs defined in  sike.saw.  
###  By directory
* /proof: SAWscript proofs 
* /spec: Cryptol code to represent SIKE algorithm
* /spec/interface: Communicates directly by Sawscript
* /spec/abstract_spec: Represents the formal specification closely
* /spec/include : CShake file
* /spec/lib : Math operations, Type definitions, and Utility functions.
* /spec/shared : Constants and Types defined for the interface

### Changes to the C Code:  
SAW is not currently able to effectively generate symbolic representations of computations of a large scale. As a result, we occasionally need to decrease the number of iterations we prove correct. The Sidh functions `EphemeralKeyGeneration_A`, `EphemeralKeyGeneration_B`, `EphemeralSecretAgreement_A`,and `EphemeralSecretAgreement_B` have loops statically bound to a large number of iterations. For these function we modified the C code to bound the for-loop to an input variable and then verified the function for a set of fixed sizes. The code was modified, by replacing the constant upper-bounds ( `MAX_Alice`)  with an input parameter (`F1`). 
