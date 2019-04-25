Code changes:  EphemeralSecretAgreement_A, EphemeralSecretAgreement_B, EphemeralKeyGeneration_A, EphemeralKeyGeneration_B

These functions had a for-loop with a high upper-bound that was difficult to verify with SAW. Instead we modified code so we could call these function with smaller numbers (used as an upper-bounds for the for-loop). The code was modified, by replacing the constant upper-bounds ( MAX_Alice)  with an input parameter (`F1`). 
