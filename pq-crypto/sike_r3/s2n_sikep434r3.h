/********************************************************************************************
* Supersingular Isogeny Key Encapsulation Library
*
* Abstract: supersingular isogeny parameters and generation of functions for P434
*********************************************************************************************/  

#pragma once

#include "s2n_sikep434r3_config.h"

#define S2N_SIKE_P434_R3_NAMESPACE(s) s2n_sike_p434_r3_##s

// Basic constants
#define NBITS_FIELD             434
#define MAXBITS_FIELD           448
#define MAXWORDS_FIELD          ((MAXBITS_FIELD+S2N_SIKE_P434_R3_RADIX-1)/S2N_SIKE_P434_R3_RADIX)     // Max. number of words to represent field elements
#define NWORDS64_FIELD          ((NBITS_FIELD+63)/64)               // Number of 64-bit words of a 434-bit field element
#define NBITS_ORDER             256
#define NWORDS_ORDER            ((NBITS_ORDER+S2N_SIKE_P434_R3_RADIX-1)/S2N_SIKE_P434_R3_RADIX)       // Number of words of oA and oB, where oA and oB are the subgroup orders of Alice and Bob, resp.
#define NWORDS64_ORDER          ((NBITS_ORDER+63)/64)               // Number of 64-bit words of a 224-bit element
#define MAXBITS_ORDER           NBITS_ORDER
#define ALICE                   0
#define BOB                     1
#define OALICE_BITS             216
#define OBOB_BITS               218
#define OBOB_EXPON              137
#define MASK_ALICE              0xFF
#define MASK_BOB                0x01
#define PRIME                   p434
#define PARAM_A                 6
#define PARAM_C                 1
// Fixed parameters for isogeny tree computation
#define MAX_INT_POINTS_ALICE    7
#define MAX_INT_POINTS_BOB      8
#define MAX_Alice               108
#define MAX_Bob                 137
#define MSG_BYTES               16
#define SECRETKEY_A_BYTES       ((OALICE_BITS + 7) / 8)
#define SECRETKEY_B_BYTES       ((OBOB_BITS - 1 + 7) / 8)
#define FP2_ENCODED_BYTES       2*((NBITS_FIELD + 7) / 8)

// SIDH's basic element definitions and point representations
typedef digit_t felm_t[S2N_SIKE_P434_R3_NWORDS_FIELD];                                 // Datatype for representing 434-bit field elements (448-bit max.)
typedef digit_t dfelm_t[2*S2N_SIKE_P434_R3_NWORDS_FIELD];                              // Datatype for representing double-precision 2x434-bit field elements (2x448-bit max.)
typedef struct felm_s {
    felm_t e[2];
} f2elm_t; // Datatype for representing quadratic extension field elements GF(p434^2)
typedef struct { f2elm_t X; f2elm_t Z; } point_proj;                  // Point representation in projective XZ Montgomery coordinates.
typedef point_proj point_proj_t[1];

// Fixed parameters for computation
#define p434 S2N_SIKE_P434_R3_NAMESPACE(p434)
extern const uint64_t p434[NWORDS64_FIELD];

#define p434x2 S2N_SIKE_P434_R3_NAMESPACE(p434x2)
extern const uint64_t p434x2[NWORDS64_FIELD];

#define p434x4 S2N_SIKE_P434_R3_NAMESPACE(p434x4)
extern const uint64_t p434x4[NWORDS64_FIELD];

#define p434p1 S2N_SIKE_P434_R3_NAMESPACE(p434p1)
extern const uint64_t p434p1[NWORDS64_FIELD];

#define A_gen S2N_SIKE_P434_R3_NAMESPACE(A_gen)
extern const uint64_t A_gen[6*NWORDS64_FIELD];

#define B_gen S2N_SIKE_P434_R3_NAMESPACE(B_gen)
extern const uint64_t B_gen[6*NWORDS64_FIELD];

#define Montgomery_R2 S2N_SIKE_P434_R3_NAMESPACE(Montgomery_R2)
extern const uint64_t Montgomery_R2[NWORDS64_FIELD];

#define Montgomery_one S2N_SIKE_P434_R3_NAMESPACE(Montgomery_one)
extern const uint64_t Montgomery_one[NWORDS64_FIELD];

#define strat_Alice S2N_SIKE_P434_R3_NAMESPACE(strat_Alice)
extern const unsigned int strat_Alice[MAX_Alice-1];

#define strat_Bob S2N_SIKE_P434_R3_NAMESPACE(strat_Bob)
extern const unsigned int strat_Bob[MAX_Bob-1];
