/********************************************************************************************
* Supersingular Isogeny Key Encapsulation Library
*
* Abstract: internal header file for P503
*********************************************************************************************/

#ifndef __P503_INTERNAL_H__
#define __P503_INTERNAL_H__

#include "sike_r1_namespace.h"
#include "api_r1.h"

#if (TARGET == TARGET_AMD64)
    #define NWORDS_FIELD    8               // Number of words of a 503-bit field element
    #define p503_ZERO_WORDS 3               // Number of "0" digits in the least significant part of p503 + 1
#elif (TARGET == TARGET_x86)
    #define NWORDS_FIELD    16
    #define p503_ZERO_WORDS 7
#elif (TARGET == TARGET_ARM)
    #define NWORDS_FIELD    16
    #define p503_ZERO_WORDS 7
#elif (TARGET == TARGET_ARM64)
    #define NWORDS_FIELD    8
    #define p503_ZERO_WORDS 3
#endif

// Basic constants

#define NBITS_FIELD             503
#define MAXBITS_FIELD           512
#define MAXWORDS_FIELD          ((MAXBITS_FIELD+RADIX-1)/RADIX)     // Max. number of words to represent field elements
#define NWORDS64_FIELD          ((NBITS_FIELD+63)/64)               // Number of 64-bit words of a 503-bit field element
#define NBITS_ORDER             256
#define NWORDS_ORDER            ((NBITS_ORDER+RADIX-1)/RADIX)       // Number of words of oA and oB, where oA and oB are the subgroup orders of Alice and Bob, resp.
#define NWORDS64_ORDER          ((NBITS_ORDER+63)/64)               // Number of 64-bit words of a 256-bit element
#define MAXBITS_ORDER           NBITS_ORDER
#define MAXWORDS_ORDER          ((MAXBITS_ORDER+RADIX-1)/RADIX)     // Max. number of words to represent elements in [1, oA-1] or [1, oB].
#define ALICE                   0
#define BOB                     1
#define OALICE_BITS             250
#define OBOB_BITS               253
#define OBOB_EXPON              159
#define MASK_ALICE              0x03
#define MASK_BOB                0x0F
#define PRIME                   p503
#define PARAM_A                 0
#define PARAM_C                 1
// Fixed parameters for isogeny tree computation
#define MAX_INT_POINTS_ALICE    7
#define MAX_INT_POINTS_BOB      8
#define MAX_Alice               125
#define MAX_Bob                 159
#define MSG_BYTES               24
#define SECRETKEY_A_BYTES       (OALICE_BITS + 7) / 8
#define SECRETKEY_B_BYTES       (OBOB_BITS + 7) / 8
#define FP2_ENCODED_BYTES       2*((NBITS_FIELD + 7) / 8)


// SIDH's basic element definitions and point representations

typedef digit_t felm_t[NWORDS_FIELD];                                 // Datatype for representing 503-bit field elements (512-bit max.)
typedef digit_t dfelm_t[2*NWORDS_FIELD];                              // Datatype for representing double-precision 2x503-bit field elements (512-bit max.)
typedef struct felm_s
{
    felm_t e[2];
} f2elm_t; // Datatype for representing quadratic extension field elements GF(p503^2)
typedef f2elm_t publickey_t[3];                                       // Datatype for representing public keys equivalent to three GF(p503^2) elements

typedef struct { f2elm_t X; f2elm_t Z; } point_proj;                  // Point representation in projective XZ Montgomery coordinates.
typedef point_proj point_proj_t[1];



/**************** Function prototypes ****************/
/************* Multiprecision functions **************/

// Copy wordsize digits, c = a, where lng(a) = nwords
void copy_words(const digit_t* a, digit_t* c, const unsigned int nwords);

// Multiprecision addition, c = a+b, where lng(a) = lng(b) = nwords. Returns the carry bit
unsigned int mp_add(const digit_t* a, const digit_t* b, digit_t* c, const unsigned int nwords);

// 503-bit multiprecision addition, c = a+b
void mp_add503(const digit_t* a, const digit_t* b, digit_t* c);
void mp_add503_asm(const digit_t* a, const digit_t* b, digit_t* c);
//void mp_addmask503_asm(const digit_t* a, const digit_t mask, digit_t* c);

// 2x503-bit multiprecision addition, c = a+b
void mp_add503x2(const digit_t* a, const digit_t* b, digit_t* c);
void mp_add503x2_asm(const digit_t* a, const digit_t* b, digit_t* c);

// Multiprecision subtraction, c = a-b, where lng(a) = lng(b) = nwords. Returns the borrow bit
unsigned int mp_sub(const digit_t* a, const digit_t* b, digit_t* c, const unsigned int nwords);
digit_t mp_sub503x2_asm(const digit_t* a, const digit_t* b, digit_t* c);

// Multiprecision right shift by one
void mp_shiftr1(digit_t* x, const unsigned int nwords);

// Digit multiplication, digit * digit -> 2-digit result
void digit_x_digit(const digit_t a, const digit_t b, digit_t* c);

// Multiprecision comba multiply, c = a*b, where lng(a) = lng(b) = nwords.
void mp_mul(const digit_t* a, const digit_t* b, digit_t* c, const unsigned int nwords);

void multiply(const digit_t* a, const digit_t* b, digit_t* c, const unsigned int nwords);

// Montgomery multiplication modulo the group order, mc = ma*mb*r' mod order, where ma,mb,mc in [0, order-1]
void Montgomery_multiply_mod_order(const digit_t* ma, const digit_t* mb, digit_t* mc, const digit_t* order, const digit_t* Montgomery_rprime);

// (Non-constant time) Montgomery inversion modulo the curve order using a^(-1) = a^(order-2) mod order
//void Montgomery_inversion_mod_order(const digit_t* ma, digit_t* mc, const digit_t* order, const digit_t* Montgomery_rprime);

void Montgomery_inversion_mod_order_bingcd(const digit_t* a, digit_t* c, const digit_t* order, const digit_t* Montgomery_rprime, const digit_t* Montgomery_R2);

// Conversion of elements in Z_r to Montgomery representation, where the order r is up to 384 bits.
void to_Montgomery_mod_order(const digit_t* a, digit_t* mc, const digit_t* order, const digit_t* Montgomery_rprime, const digit_t* Montgomery_Rprime);

// Conversion of elements in Z_r from Montgomery to standard representation, where the order is up to 384 bits.
void from_Montgomery_mod_order(const digit_t* ma, digit_t* c, const digit_t* order, const digit_t* Montgomery_rprime);

// Inversion modulo Alice's order 2^372.
void inv_mod_orderA(const digit_t* a, digit_t* c);

/************ Field arithmetic functions *************/

// Copy of a field element, c = a
void fpcopy503(const felm_t a, felm_t c);

// Zeroing a field element, a = 0
void fpzero503(felm_t a);

// Non constant-time comparison of two field elements. If a = b return TRUE, otherwise, return FALSE
bool fpequal503_non_constant_time(const felm_t a, const felm_t b);

// Modular addition, c = a+b mod p503
extern void fpadd503(const digit_t* a, const digit_t* b, digit_t* c);
extern void fpadd503_asm(const digit_t* a, const digit_t* b, digit_t* c);

// Modular subtraction, c = a-b mod p503
extern void fpsub503(const digit_t* a, const digit_t* b, digit_t* c);
extern void fpsub503_asm(const digit_t* a, const digit_t* b, digit_t* c);

// Modular negation, a = -a mod p503
extern void fpneg503(digit_t* a);

// Modular division by two, c = a/2 mod p503.
void fpdiv2_503(const digit_t* a, digit_t* c);

// Modular correction to reduce field element a in [0, 2*p503-1] to [0, p503-1].
void fpcorrection503(digit_t* a);

// 503-bit Montgomery reduction, c = a mod p
void rdc_mont(const digit_t* a, digit_t* c);

// Field multiplication using Montgomery arithmetic, c = a*b*R^-1 mod p503, where R=2^768
void fpmul503_mont(const felm_t a, const felm_t b, felm_t c);
void mul503_asm(const felm_t a, const felm_t b, dfelm_t c);
void rdc503_asm(const dfelm_t ma, dfelm_t mc);

// Field squaring using Montgomery arithmetic, c = a*b*R^-1 mod p503, where R=2^768
void fpsqr503_mont(const felm_t ma, felm_t mc);

// Conversion to Montgomery representation
void to_mont(const felm_t a, felm_t mc);

// Conversion from Montgomery representation to standard representation
void from_mont(const felm_t ma, felm_t c);

// Field inversion, a = a^-1 in GF(p503)
void fpinv503_mont(felm_t a);

// Field inversion, a = a^-1 in GF(p503) using the binary GCD
void fpinv503_mont_bingcd(felm_t a);

// Chain to compute (p503-3)/4 using Montgomery arithmetic
void fpinv503_chain_mont(felm_t a);

/************ GF(p^2) arithmetic functions *************/

// Copy of a GF(p503^2) element, c = a
void fp2copy503(const f2elm_t *a, f2elm_t *c);

// GF(p503^2) negation, a = -a in GF(p503^2)
void fp2neg503(f2elm_t *a);

// GF(p503^2) addition, c = a+b in GF(p503^2)
extern void fp2add503(const f2elm_t *a, const f2elm_t *b, f2elm_t *c);

// GF(p503^2) subtraction, c = a-b in GF(p503^2)
extern void fp2sub503(const f2elm_t *a, const f2elm_t *b, f2elm_t *c);

// GF(p503^2) division by two, c = a/2  in GF(p503^2)
void fp2div2_503(const f2elm_t *a, f2elm_t *c);

// Modular correction, a = a in GF(p503^2)
void fp2correction503(f2elm_t *a);

// GF(p503^2) squaring using Montgomery arithmetic, c = a^2 in GF(p503^2)
void fp2sqr503_mont(const f2elm_t *a, f2elm_t *c);

// GF(p503^2) multiplication using Montgomery arithmetic, c = a*b in GF(p503^2)
void fp2mul503_mont(const f2elm_t *a, const f2elm_t *b, f2elm_t *c);

// Conversion of a GF(p503^2) element to Montgomery representation
void to_fp2mont(const f2elm_t *a, f2elm_t *mc);

// Conversion of a GF(p503^2) element from Montgomery representation to standard representation
void from_fp2mont(const f2elm_t *ma, f2elm_t *c);

// GF(p503^2) inversion using Montgomery arithmetic, a = (a0-i*a1)/(a0^2+a1^2)
void fp2inv503_mont(f2elm_t *a);

// GF(p503^2) inversion, a = (a0-i*a1)/(a0^2+a1^2), GF(p503) inversion done using the binary GCD
void fp2inv503_mont_bingcd(f2elm_t *a);

// n-way Montgomery inversion
void mont_n_way_inv(const f2elm_t* vec, const int n, f2elm_t* out);

/************ Elliptic curve and isogeny functions *************/

// Computes the j-invariant of a Montgomery curve with projective constant.
void j_inv(const f2elm_t *A, const f2elm_t *C, f2elm_t *jinv);

// Simultaneous doubling and differential addition.
void xDBLADD(point_proj_t P, point_proj_t Q, const f2elm_t *xPQ, const f2elm_t *A24);

// Doubling of a Montgomery point in projective coordinates (X:Z).
void xDBL(const point_proj_t P, point_proj_t Q, const f2elm_t *A24plus, const f2elm_t *C24);

// Computes [2^e](X:Z) on Montgomery curve with projective constant via e repeated doublings.
void xDBLe(const point_proj_t P, point_proj_t Q, const f2elm_t *A24plus, const f2elm_t *C24, const int e);

// Differential addition.
void xADD(point_proj_t P, const point_proj_t Q, const f2elm_t *xPQ);

// Computes the corresponding 4-isogeny of a projective Montgomery point (X4:Z4) of order 4.
void get_4_isog(const point_proj_t P, f2elm_t *A24plus, f2elm_t *C24, f2elm_t* coeff);

// Evaluates the isogeny at the point (X:Z) in the domain of the isogeny.
void eval_4_isog(point_proj_t P, f2elm_t* coeff);

// Tripling of a Montgomery point in projective coordinates (X:Z).
void xTPL(const point_proj_t P, point_proj_t Q, const f2elm_t *A24minus, const f2elm_t *A24plus);

// Computes [3^e](X:Z) on Montgomery curve with projective constant via e repeated triplings.
void xTPLe(const point_proj_t P, point_proj_t Q, const f2elm_t *A24minus, const f2elm_t *A24plus, const int e);

// Computes the corresponding 3-isogeny of a projective Montgomery point (X3:Z3) of order 3.
void get_3_isog(const point_proj_t P, f2elm_t *A24minus, f2elm_t *A24plus, f2elm_t* coeff);

// Computes the 3-isogeny R=phi(X:Z), given projective point (X3:Z3) of order 3 on a Montgomery curve and a point P with coefficients given in coeff.
void eval_3_isog(point_proj_t Q, const f2elm_t* coeff);

// 3-way simultaneous inversion
void inv_3_way(f2elm_t *z1, f2elm_t *z2, f2elm_t *z3);

// Given the x-coordinates of P, Q, and R, returns the value A corresponding to the Montgomery curve E_A: y^2=x^3+A*x^2+x such that R=Q-P on E_A.
void get_A(const f2elm_t *xP, const f2elm_t *xQ, const f2elm_t *xR, f2elm_t *A);


#endif
