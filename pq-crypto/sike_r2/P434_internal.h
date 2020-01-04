/********************************************************************************************
* SIDH: an efficient supersingular isogeny cryptography library
*
* Abstract: internal header file for P434
*********************************************************************************************/

#ifndef P434_INTERNAL_H
#define P434_INTERNAL_H

#include "config.h"

#if (TARGET == TARGET_AMD64)
#define NWORDS_FIELD 7    // Number of words of a 434-bit field element
#define p434_ZERO_WORDS 3 // Number of "0" digits in the least significant part of p434 + 1
#elif (TARGET == TARGET_x86)
#define NWORDS_FIELD 14
#define p434_ZERO_WORDS 6
#elif (TARGET == TARGET_ARM)
#define NWORDS_FIELD 14
#define p434_ZERO_WORDS 6
#elif (TARGET == TARGET_ARM64)
#define NWORDS_FIELD 7
#define p434_ZERO_WORDS 3
#endif

// Basic constants

#define NBITS_FIELD 434
#define MAXBITS_FIELD 448
#define MAXWORDS_FIELD ((MAXBITS_FIELD + RADIX - 1) / RADIX) // Max. number of words to represent field elements
#define NWORDS64_FIELD ((NBITS_FIELD + 63) / 64)             // Number of 64-bit words of a 434-bit field element
#define NBITS_ORDER 256
#define NWORDS_ORDER ((NBITS_ORDER + RADIX - 1) / RADIX) // Number of words of oA and oB, where oA and oB are the subgroup orders of Alice and Bob, resp.
#define NWORDS64_ORDER ((NBITS_ORDER + 63) / 64)         // Number of 64-bit words of a 224-bit element
#define MAXBITS_ORDER NBITS_ORDER
#define ALICE 0
#define BOB 1
#define OALICE_BITS 216
#define OBOB_BITS 218
#define OBOB_EXPON 137
#define MASK_ALICE 0xFF
#define MASK_BOB 0x01
#define PRIME p434
#define PARAM_A 6
#define PARAM_C 1
// Fixed parameters for isogeny tree computation
#define MAX_INT_POINTS_ALICE 7
#define MAX_INT_POINTS_BOB 8
#define MAX_Alice 108
#define MAX_Bob 137
#define MSG_BYTES 16
#define SECRETKEY_A_BYTES ((OALICE_BITS + 7) / 8)
#define SECRETKEY_B_BYTES ((OBOB_BITS - 1 + 7) / 8)
#define FP2_ENCODED_BYTES 2 * ((NBITS_FIELD + 7) / 8)

// SIDH's basic element definitions and point representations

typedef digit_t felm_t[NWORDS_FIELD];      // Datatype for representing 434-bit field elements (448-bit max.)
typedef digit_t dfelm_t[2 * NWORDS_FIELD]; // Datatype for representing double-precision 2x434-bit field elements (448-bit max.)
typedef struct felm_s {
    felm_t e[2];
} f2elm_t; // Datatype for representing quadratic extension field elements GF(p434^2)

typedef struct {
	f2elm_t X;
	f2elm_t Z;
} point_proj; // Point representation in projective XZ Montgomery coordinates.
typedef point_proj point_proj_t[1];

/**************** Function prototypes ****************/
/************* Multiprecision functions **************/

// Copy wordsize digits, c = a, where lng(a) = nwords
void copy_words(const digit_t *a, digit_t *c, const unsigned int nwords);

// Multiprecision addition, c = a+b, where lng(a) = lng(b) = nwords. Returns the carry bit
unsigned int mp_add(const digit_t *a, const digit_t *b, digit_t *c, const unsigned int nwords);

// 434-bit multiprecision addition, c = a+b
void mp_add434_asm(const digit_t *a, const digit_t *b, digit_t *c);

// Multiprecision subtraction, c = a-b, where lng(a) = lng(b) = nwords. Returns the borrow bit
unsigned int mp_sub(const digit_t *a, const digit_t *b, digit_t *c, const unsigned int nwords);

// 2x434-bit multiprecision subtraction followed by addition with p434*2^448, c = a-b+(p434*2^448) if a-b < 0, otherwise c=a-b
void mp_subaddx2_asm(const digit_t *a, const digit_t *b, digit_t *c);
void mp_subadd434x2_asm(const digit_t *a, const digit_t *b, digit_t *c);

// Double 2x434-bit multiprecision subtraction, c = c-a-b, where c > a and c > b
void mp_dblsub434x2_asm(const digit_t *a, const digit_t *b, digit_t *c);

// Multiprecision right shift by one
void mp_shiftr1(digit_t *x, const unsigned int nwords);

// Digit multiplication, digit * digit -> 2-digit result
void digit_x_digit(const digit_t a, const digit_t b, digit_t *c);

// Multiprecision comba multiply, c = a*b, where lng(a) = lng(b) = nwords.
void mp_mul(const digit_t *a, const digit_t *b, digit_t *c, const unsigned int nwords);

/************ Field arithmetic functions *************/

// Copy of a field element, c = a
void fpcopy434(const digit_t *a, digit_t *c);

// Zeroing a field element, a = 0
void fpzero434(digit_t *a);

// Modular addition, c = a+b mod p434
extern void fpadd434(const digit_t *a, const digit_t *b, digit_t *c);
extern void fpadd434_asm(const digit_t *a, const digit_t *b, digit_t *c);

// Modular subtraction, c = a-b mod p434
extern void fpsub434(const digit_t *a, const digit_t *b, digit_t *c);
extern void fpsub434_asm(const digit_t *a, const digit_t *b, digit_t *c);

// Modular negation, a = -a mod p434
extern void fpneg434(digit_t *a);

// Modular division by two, c = a/2 mod p434.
void fpdiv2_434(const digit_t *a, digit_t *c);

// Modular correction to reduce field element a in [0, 2*p434-1] to [0, p434-1].
void fpcorrection434(digit_t *a);

// 434-bit Montgomery reduction, c = a mod p
void rdc_mont(const digit_t *a, digit_t *c);

// Field multiplication using Montgomery arithmetic, c = a*b*R^-1 mod p434, where R=2^768
void fpmul434_mont(const digit_t *a, const digit_t *b, digit_t *c);
void mul434_asm(const digit_t *a, const digit_t *b, digit_t *c);
void rdc434_asm(const digit_t *ma, digit_t *mc);

// Field squaring using Montgomery arithmetic, c = a*b*R^-1 mod p434, where R=2^768
void fpsqr434_mont(const digit_t *ma, digit_t *mc);

// Conversion to Montgomery representation
void to_mont(const digit_t *a, digit_t *mc);

// Conversion from Montgomery representation to standard representation
void from_mont(const digit_t *ma, digit_t *c);

// Field inversion, a = a^-1 in GF(p434)
void fpinv434_mont(digit_t *a);

// Chain to compute (p434-3)/4 using Montgomery arithmetic
void fpinv434_chain_mont(digit_t *a);

/************ GF(p^2) arithmetic functions *************/

// Copy of a GF(p434^2) element, c = a
void fp2copy434(const f2elm_t *a, f2elm_t *c);

// Zeroing a GF(p434^2) element, a = 0
void fp2zero434(f2elm_t *a);

// GF(p434^2) negation, a = -a in GF(p434^2)
void fp2neg434(f2elm_t *a);

// GF(p434^2) addition, c = a+b in GF(p434^2)
void fp2add434(const f2elm_t *a, const f2elm_t *b, f2elm_t *c);

// GF(p434^2) subtraction, c = a-b in GF(p434^2)
extern void fp2sub434(const f2elm_t *a, const f2elm_t *b, f2elm_t *c);

// GF(p434^2) division by two, c = a/2  in GF(p434^2)
void fp2div2_434(const f2elm_t *a, f2elm_t *c);

// Modular correction, a = a in GF(p434^2)
void fp2correction434(f2elm_t *a);

// GF(p434^2) squaring using Montgomery arithmetic, c = a^2 in GF(p434^2)
void fp2sqr434_mont(const f2elm_t *a, f2elm_t *c);

// GF(p434^2) multiplication using Montgomery arithmetic, c = a*b in GF(p434^2)
void fp2mul434_mont(const f2elm_t *a, const f2elm_t *b, f2elm_t *c);

// Conversion of a GF(p434^2) element to Montgomery representation
void to_fp2mont(const f2elm_t *a, f2elm_t *mc);

// Conversion of a GF(p434^2) element from Montgomery representation to standard representation
void from_fp2mont(const f2elm_t *ma, f2elm_t *c);

// GF(p434^2) inversion using Montgomery arithmetic, a = (a0-i*a1)/(a0^2+a1^2)
void fp2inv434_mont(f2elm_t *a);

/************ Elliptic curve and isogeny functions *************/

// Computes the j-invariant of a Montgomery curve with projective constant.
void j_inv(const f2elm_t *A, const f2elm_t *C, f2elm_t *jinv);

// Simultaneous doubling and differential addition.
void xDBLADD(point_proj_t P, point_proj_t Q, const f2elm_t *xPQ, const f2elm_t *A24);

// Doubling of a Montgomery point in projective coordinates (X:Z).
void xDBL(const point_proj_t P, point_proj_t Q, const f2elm_t *A24plus, const f2elm_t *C24);

// Computes [2^e](X:Z) on Montgomery curve with projective constant via e repeated doublings.
void xDBLe(const point_proj_t P, point_proj_t Q, const f2elm_t *A24plus, const f2elm_t *C24, const int e);

// Computes the corresponding 4-isogeny of a projective Montgomery point (X4:Z4) of order 4.
void get_4_isog(const point_proj_t P, f2elm_t *A24plus, f2elm_t *C24, f2elm_t *coeff);

// Evaluates the isogeny at the point (X:Z) in the domain of the isogeny.
void eval_4_isog(point_proj_t P, f2elm_t *coeff);

// Tripling of a Montgomery point in projective coordinates (X:Z).
void xTPL(const point_proj_t P, point_proj_t Q, const f2elm_t *A24minus, const f2elm_t *A24plus);

// Computes [3^e](X:Z) on Montgomery curve with projective constant via e repeated triplings.
void xTPLe(const point_proj_t P, point_proj_t Q, const f2elm_t *A24minus, const f2elm_t *A24plus, const int e);

// Computes the corresponding 3-isogeny of a projective Montgomery point (X3:Z3) of order 3.
void get_3_isog(const point_proj_t P, f2elm_t *A24minus, f2elm_t *A24plus, f2elm_t *coeff);

// Computes the 3-isogeny R=phi(X:Z), given projective point (X3:Z3) of order 3 on a Montgomery curve and a point P with coefficients given in coeff.
void eval_3_isog(point_proj_t Q, const f2elm_t *coeff);

// 3-way simultaneous inversion
void inv_3_way(f2elm_t *z1, f2elm_t *z2, f2elm_t *z3);

// Given the x-coordinates of P, Q, and R, returns the value A corresponding to the Montgomery curve E_A: y^2=x^3+A*x^2+x such that R=Q-P on E_A.
void get_A(const f2elm_t *xP, const f2elm_t *xQ, const f2elm_t *xR, f2elm_t *A);

#endif
