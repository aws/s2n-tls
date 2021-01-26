/********************************************************************************************
* Supersingular Isogeny Key Encapsulation Library
*
* Abstract: internal header file for P434
*********************************************************************************************/  

#ifndef P434_INTERNAL_H
#define P434_INTERNAL_H

#include "../config.h"
 

#if (TARGET == TARGET_AMD64) || (TARGET == TARGET_ARM64) || (TARGET == TARGET_S390X)
    #define NWORDS_FIELD    7               // Number of words of a 434-bit field element
    #define p434_ZERO_WORDS 3               // Number of "0" digits in the least significant part of p434 + 1     
#elif (TARGET == TARGET_x86) || (TARGET == TARGET_ARM)
    #define NWORDS_FIELD    14 
    #define p434_ZERO_WORDS 6
#endif
    

// Basic constants

#define NBITS_FIELD             434  
#define MAXBITS_FIELD           448                
#define MAXWORDS_FIELD          ((MAXBITS_FIELD+RADIX-1)/RADIX)     // Max. number of words to represent field elements
#define NWORDS64_FIELD          ((NBITS_FIELD+63)/64)               // Number of 64-bit words of a 434-bit field element 
#define NBITS_ORDER             256
#define NWORDS_ORDER            ((NBITS_ORDER+RADIX-1)/RADIX)       // Number of words of oA and oB, where oA and oB are the subgroup orders of Alice and Bob, resp.
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

#ifdef COMPRESS
    #define MASK2_BOB               0x00
    #define MASK3_BOB               0x7F
    #define ORDER_A_ENCODED_BYTES   SECRETKEY_A_BYTES
    #define ORDER_B_ENCODED_BYTES   SECRETKEY_B_BYTES
    #define PARTIALLY_COMPRESSED_CHUNK_CT     (4*ORDER_A_ENCODED_BYTES + FP2_ENCODED_BYTES + 2)
    #define COMPRESSED_CHUNK_CT     (3*ORDER_A_ENCODED_BYTES + FP2_ENCODED_BYTES + 2)
    #define UNCOMPRESSEDPK_BYTES    330
    // Table sizes used by the Entangled basis generation
    #define TABLE_R_LEN 17
    #define TABLE_V_LEN 34
    #define TABLE_V3_LEN 20
    // Parameters for discrete log computations
    // Binary Pohlig-Hellman reduced to smaller logs of order ell^W
    #define W_2 4
    #define W_3 3
    // ell^w    
    #define ELL2_W (1 << W_2)    
    #define ELL3_W 27
    // ell^(e mod w) 
    #define ELL2_EMODW (1 << (OALICE_BITS % W_2))    
    #define ELL3_EMODW 9
    // # of digits in the discrete log    
    #define DLEN_2 ((OALICE_BITS+W_2-1)/W_2) // ceil(eA/W_2)
    #define DLEN_3 ((OBOB_EXPON+W_3-1)/W_3)  // ceil(eB/W_3)
    // Use compressed tables: FULL_SIGNED
    #define COMPRESSED_TABLES
    #define ELL2_FULL_SIGNED    // Uses signed digits to reduce table size by half
    #define ELL3_FULL_SIGNED    // Uses signed digits to reduce table size by half
    // Length of the optimal strategy path for Pohlig-Hellman
    #ifdef COMPRESSED_TABLES
        #ifdef ELL2_FULL_SIGNED
            #if W_2 == 4
                #define PLEN_2 55
            #endif
            #if W_3 == 3
                #define PLEN_3 47
            #endif
        #endif
    #endif
#endif


// SIDH's basic element definitions and point representations

typedef digit_t felm_t[NWORDS_FIELD];                                 // Datatype for representing 434-bit field elements (448-bit max.)
typedef digit_t dfelm_t[2*NWORDS_FIELD];                              // Datatype for representing double-precision 2x434-bit field elements (2x448-bit max.) 
typedef felm_t  f2elm_t[2];                                           // Datatype for representing quadratic extension field elements GF(p434^2)
        
typedef struct { f2elm_t X; f2elm_t Z; } point_proj;                  // Point representation in projective XZ Montgomery coordinates.
typedef point_proj point_proj_t[1]; 

#ifdef COMPRESS
    typedef struct { f2elm_t X; f2elm_t Y; f2elm_t Z; } point_full_proj;  // Point representation in full projective XYZ Montgomery coordinates 
    typedef point_full_proj point_full_proj_t[1]; 

    typedef struct { f2elm_t x; f2elm_t y; } point_affine;                // Point representation in affine coordinates.
    typedef point_affine point_t[1]; 

    typedef f2elm_t publickey_t[3];      
#endif


/**************** Function prototypes ****************/
/************* Multiprecision functions **************/

// 434-bit multiprecision addition, c = a+b
void mp_add434(const digit_t* a, const digit_t* b, digit_t* c);
void mp_add434_asm(const digit_t* a, const digit_t* b, digit_t* c);

// 434-bit multiprecision subtraction, c = a-b+2p or c = a-b+4p
extern void mp_sub434_p2(const digit_t* a, const digit_t* b, digit_t* c);
extern void mp_sub434_p4(const digit_t* a, const digit_t* b, digit_t* c);
void mp_sub434_p2_asm(const digit_t* a, const digit_t* b, digit_t* c); 
void mp_sub434_p4_asm(const digit_t* a, const digit_t* b, digit_t* c); 

// 2x434-bit multiprecision subtraction followed by addition with p434*2^448, c = a-b+(p434*2^448) if a-b < 0, otherwise c=a-b 
void mp_subaddx2_asm(const digit_t* a, const digit_t* b, digit_t* c);
void mp_subadd434x2_asm(const digit_t* a, const digit_t* b, digit_t* c);

// Double 2x434-bit multiprecision subtraction, c = c-a-b, where c > a and c > b
void mp_dblsub434x2_asm(const digit_t* a, const digit_t* b, digit_t* c);

/************ Field arithmetic functions *************/

// Copy of a field element, c = a
void fpcopy434(const digit_t* a, digit_t* c);

// Zeroing a field element, a = 0
void fpzero434(digit_t* a);

// Non constant-time comparison of two field elements. If a = b return TRUE, otherwise, return FALSE
bool fpequal434_non_constant_time(const digit_t* a, const digit_t* b); 

// Modular addition, c = a+b mod p434
extern void fpadd434(const digit_t* a, const digit_t* b, digit_t* c);
extern void fpadd434_asm(const digit_t* a, const digit_t* b, digit_t* c);

// Modular subtraction, c = a-b mod p434
extern void fpsub434(const digit_t* a, const digit_t* b, digit_t* c);
extern void fpsub434_asm(const digit_t* a, const digit_t* b, digit_t* c);

// Modular negation, a = -a mod p434        
extern void fpneg434(digit_t* a);  

// Modular division by two, c = a/2 mod p434.
void fpdiv2_434(const digit_t* a, digit_t* c);

// Modular correction to reduce field element a in [0, 2*p434-1] to [0, p434-1].
void fpcorrection434(digit_t* a);

// 434-bit Montgomery reduction, c = a mod p
void rdc434_asm(digit_t* ma, digit_t* mc);
            
// Field multiplication using Montgomery arithmetic, c = a*b*R^-1 mod p434, where R=2^768
void fpmul434_mont(const digit_t* a, const digit_t* b, digit_t* c);
void mul434_asm(const digit_t* a, const digit_t* b, digit_t* c);
   
// Field squaring using Montgomery arithmetic, c = a*b*R^-1 mod p434, where R=2^768
void fpsqr434_mont(const digit_t* ma, digit_t* mc);

// Field inversion, a = a^-1 in GF(p434)
void fpinv434_mont(digit_t* a);

// Field inversion, a = a^-1 in GF(p434) using the binary GCD 
void fpinv434_mont_bingcd(digit_t* a);

// Chain to compute (p434-3)/4 using Montgomery arithmetic
void fpinv434_chain_mont(digit_t* a);

/************ GF(p^2) arithmetic functions *************/
    
// Copy of a GF(p434^2) element, c = a
void fp2copy434(const f2elm_t a, f2elm_t c);

// Zeroing a GF(p434^2) element, a = 0
void fp2zero434(f2elm_t a);

// GF(p434^2) negation, a = -a in GF(p434^2)
void fp2neg434(f2elm_t a);

// GF(p434^2) addition, c = a+b in GF(p434^2)
extern void fp2add434(const f2elm_t a, const f2elm_t b, f2elm_t c);           

// GF(p434^2) subtraction, c = a-b in GF(p434^2)
extern void fp2sub434(const f2elm_t a, const f2elm_t b, f2elm_t c); 

// GF(p434^2) division by two, c = a/2  in GF(p434^2) 
void fp2div2_434(const f2elm_t a, f2elm_t c);

// Modular correction, a = a in GF(p434^2)
void fp2correction434(f2elm_t a);
            
// GF(p434^2) squaring using Montgomery arithmetic, c = a^2 in GF(p434^2)
void fp2sqr434_mont(const f2elm_t a, f2elm_t c);
 
// GF(p434^2) multiplication using Montgomery arithmetic, c = a*b in GF(p434^2)
void fp2mul434_mont(const f2elm_t a, const f2elm_t b, f2elm_t c);

// GF(p434^2) inversion using Montgomery arithmetic, a = (a0-i*a1)/(a0^2+a1^2)
void fp2inv434_mont(f2elm_t a);

// GF(p434^2) inversion, a = (a0-i*a1)/(a0^2+a1^2), GF(p434) inversion done using the binary GCD 
void fp2inv434_mont_bingcd(f2elm_t a);


#endif
