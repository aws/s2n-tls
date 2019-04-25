We verified the C implementation of the Supersingular Isogeny Key Encapsulation (SIKE) algorithm using the SAW tool and Cryptol language. Due to the complexity of SIKE, we applied different verification approaches for different portions of the code. These provide varying levels of assurance, i.e. they each rule out specific categories of errors in the code: 

## Approaches 
- Approach 1 (strongest): verification of the mathematical behaviour of the code. Finite field operations were verified with this approach.  
- Approach 2: verification of the operational behaviour of the code, guaranteeing the absence of program errors. Most of the rest of SIKE was verified in this way. 
- Approach 3 (weakest): verification of operational behaviour with additional simplifying assumptions, for example bounding the size of inputs or iterations in a loop. 
We applied these approaches so as to maximize the assurance we achieved with the time / resources available. We also omitted a very small number of functions as a result of limitations in our verification tools. 

## Organization
###  By mathematical concept and SIKE file
| Description | SIKE file  | Cryptol Specification           | SAW Proof |
| ------------- | -----: |:-------------:| -----:|
| Low-level field operators (fp) | fp_generic.c     |  fp_generic.cry . | field.saw & word.saw |
| Higher-level field operators (fp2)| fpx.c | fpx.cry  |  field.saw & word.saw |
| Random functions | random.c|         | random.saw
| Base math operations | config.h | fp_generic.cry  & fpx.cry | word.saw
| Isogeny Functions |  ec_isogeny.c | ec_isogeny.cry | curv.saw &  isogeny.saw
| Key generation and encoding | sidh.h | sidh.cry | word.saw & sidh.saw
| SIKE top-level |  sike.c | sike.cry | sike.saw
| CShake |  flips202.c | Keccak.cry | cshake.saw

###  By directory
* /proof: SAWscript proofs 
* /spec: Cryptol code to represent SIKE algorithm
* /spec/interface: Communicates directly by Sawscript
* /spec/abstract_spec: Represents the formal specification closely
* /spec/include : CShake file
* /spec/lib : Math operations, Type definitions, and Utility functions.
* /spec/shared : Constants and Types defined for the interface

### Changes to the C Code:  
SAW is not currently able to effectively generate symbolic representations of computations of a large scale. As a result, we occasionally need to decrease the number of iterations we prove correct. The SIDH functions `EphemeralKeyGeneration_A`, `EphemeralKeyGeneration_B`, `EphemeralSecretAgreement_A`,and `EphemeralSecretAgreement_B` have loops statically bound to a large number of iterations. For these function we modified the C code to bound the for-loop to an input variable and then verified the function for a set of fixed sizes. The code was modified, by replacing the constant upper-bounds ( `MAX_Alice`)  with an input parameter (`F1`). 
