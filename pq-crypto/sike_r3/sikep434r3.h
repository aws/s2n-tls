/********************************************************************************************
* Supersingular Isogeny Key Encapsulation Library
*
* Abstract: supersingular isogeny parameters, generation of functions for P434;
*           configuration and platform-dependent macros
*********************************************************************************************/  

#pragma once

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

/* All sikep434r3 functions and global variables in the pq-crypto/sike_r3 directory
 * should be defined using this namespace macro to avoid symbol collisions. For example,
 * in foo.h, declare a function as follows:
 *
 * #define foo_function S2N_SIKE_P434_R3_NAMESPACE(foo_function)
 * int foo_function(int foo_argument); */
#define S2N_SIKE_P434_R3_NAMESPACE(s) s2n_sike_p434_r3_##s

/* Endian-related functionality */
/* Returns true if the machine is big endian */
#define is_big_endian S2N_SIKE_P434_R3_NAMESPACE(is_big_endian)
bool is_big_endian(void);

#define bswap32 S2N_SIKE_P434_R3_NAMESPACE(bswap32)
uint32_t bswap32(uint32_t x);

#define bswap64 S2N_SIKE_P434_R3_NAMESPACE(bswap64)
uint64_t bswap64(uint64_t x);

/* Arch specific definitions */
#define digit_t S2N_SIKE_P434_R3_NAMESPACE(digit_t)
#define hdigit_t S2N_SIKE_P434_R3_NAMESPACE(hdigit_t)
#if defined(_AMD64_) || defined(__x86_64) || defined(__x86_64__) || defined(__aarch64__) || defined(_S390X_) || defined(_ARM64_) || defined(__powerpc64__) || (defined(__riscv) && (__riscv_xlen == 64))
    #define S2N_SIKE_P434_R3_NWORDS_FIELD    7 /* Number of words of a 434-bit field element */
    #define S2N_SIKE_P434_R3_ZERO_WORDS      3 /* Number of "0" digits in the least significant part of p434 + 1 */
    #define S2N_SIKE_P434_R3_RADIX           64
    #define S2N_SIKE_P434_R3_LOG2RADIX       6
    #define S2N_SIKE_P434_R3_BSWAP_DIGIT(i)  bswap64((i))
    typedef uint64_t digit_t;
    typedef uint32_t hdigit_t;
#elif defined(_X86_) || defined(_ARM_) || defined(__arm__) || defined(__i386__)
    #define S2N_SIKE_P434_R3_NWORDS_FIELD    14 /* Number of words of a 434-bit field element */
    #define S2N_SIKE_P434_R3_ZERO_WORDS      6  /* Number of "0" digits in the least significant part of p434 + 1 */
    #define S2N_SIKE_P434_R3_RADIX           32
    #define S2N_SIKE_P434_R3_LOG2RADIX       5
    #define S2N_SIKE_P434_R3_BSWAP_DIGIT(i)  bswap32((i))
    typedef uint32_t digit_t;
    typedef uint16_t hdigit_t;
#else
    #error -- "Unsupported ARCHITECTURE"
#endif

/* Basic constants */
#define S2N_SIKE_P434_R3_NBITS_FIELD     434
#define S2N_SIKE_P434_R3_MAXBITS_FIELD   448
/* Number of 64-bit words of a 434-bit field element */
#define S2N_SIKE_P434_R3_NWORDS64_FIELD  ((S2N_SIKE_P434_R3_NBITS_FIELD+63)/64)
#define S2N_SIKE_P434_R3_NBITS_ORDER     256
/* Number of words of oA and oB, where oA and oB are the subgroup orders of Alice and Bob, resp. */
#define S2N_SIKE_P434_R3_NWORDS_ORDER    ((S2N_SIKE_P434_R3_NBITS_ORDER+S2N_SIKE_P434_R3_RADIX-1)/S2N_SIKE_P434_R3_RADIX)
#define S2N_SIKE_P434_R3_ALICE           0
#define S2N_SIKE_P434_R3_BOB             1
#define S2N_SIKE_P434_R3_OALICE_BITS     216
#define S2N_SIKE_P434_R3_OBOB_BITS       218
#define S2N_SIKE_P434_R3_MASK_ALICE      0xFF
#define S2N_SIKE_P434_R3_MASK_BOB        0x01

/* Fixed parameters for isogeny tree computation */
#define S2N_SIKE_P434_R3_MAX_INT_POINTS_ALICE    7
#define S2N_SIKE_P434_R3_MAX_INT_POINTS_BOB      8
#define S2N_SIKE_P434_R3_MAX_ALICE               108
#define S2N_SIKE_P434_R3_MAX_BOB                 137
#define S2N_SIKE_P434_R3_MSG_BYTES               16
#define S2N_SIKE_P434_R3_SECRETKEY_A_BYTES       ((S2N_SIKE_P434_R3_OALICE_BITS + 7) / 8)
#define S2N_SIKE_P434_R3_SECRETKEY_B_BYTES       ((S2N_SIKE_P434_R3_OBOB_BITS - 1 + 7) / 8)
#define S2N_SIKE_P434_R3_FP2_ENCODED_BYTES       (2 * ((S2N_SIKE_P434_R3_NBITS_FIELD + 7) / 8))

/* SIDH's basic element definitions and point representations */
/* Datatype for representing 434-bit field elements (448-bit max.) */
#define felm_t S2N_SIKE_P434_R3_NAMESPACE(felm_t)
typedef digit_t felm_t[S2N_SIKE_P434_R3_NWORDS_FIELD];

/* Datatype for representing double-precision 2x434-bit field elements (2x448-bit max.) */
#define dfelm_t S2N_SIKE_P434_R3_NAMESPACE(dfelm_t)
typedef digit_t dfelm_t[2*S2N_SIKE_P434_R3_NWORDS_FIELD];

/* Datatype for representing quadratic extension field elements GF(p434^2) */
#define f2elm_t S2N_SIKE_P434_R3_NAMESPACE(f2elm_t)
#define felm_s S2N_SIKE_P434_R3_NAMESPACE(felm_s)
typedef struct felm_s {
    felm_t e[2];
} f2elm_t;

/* Point representation in projective XZ Montgomery coordinates. */
#define point_proj S2N_SIKE_P434_R3_NAMESPACE(point_proj)
typedef struct { f2elm_t X; f2elm_t Z; } point_proj;
#define point_proj_t S2N_SIKE_P434_R3_NAMESPACE(point_proj_t)
typedef point_proj point_proj_t[1];

/********************** Constant-time unsigned comparisons ***********************/
/* The following functions return 1 (TRUE) if condition is true, 0 (FALSE) otherwise */

/* Is x != 0? */
static __inline unsigned int is_digit_nonzero_ct(const digit_t x)
{
    return (unsigned int)((x | (0-x)) >> (S2N_SIKE_P434_R3_RADIX-1));
}

/* Is x = 0? */
static __inline unsigned int is_digit_zero_ct(const digit_t x)
{
    return (unsigned int)(1 ^ is_digit_nonzero_ct(x));
}

/* Is x < y? */
static __inline unsigned int is_digit_lessthan_ct(const digit_t x, const digit_t y)
{
    return (unsigned int)((x ^ ((x ^ y) | ((x - y) ^ y))) >> (S2N_SIKE_P434_R3_RADIX-1));
}

/* Definitions for generic C implementation */

typedef uint64_t uint128_t[2];

/* Digit multiplication */
#define S2N_SIKE_P434_R3_MUL(multiplier, multiplicand, hi, lo)                                    \
    digit_x_digit((multiplier), (multiplicand), &(lo));

/* Digit addition with carry */
#define S2N_SIKE_P434_R3_ADDC(carryIn, addend1, addend2, carryOut, sumOut)                        \
    { digit_t tempReg = (addend1) + (digit_t)(carryIn);                                           \
    (sumOut) = (addend2) + tempReg;                                                               \
    (carryOut) = (is_digit_lessthan_ct(tempReg, (digit_t)(carryIn)) | is_digit_lessthan_ct((sumOut), tempReg)); }

/* Digit subtraction with borrow */
#define S2N_SIKE_P434_R3_SUBC(borrowIn, minuend, subtrahend, borrowOut, differenceOut)            \
    { digit_t tempReg = (minuend) - (subtrahend);                                                 \
    unsigned int borrowReg = (is_digit_lessthan_ct((minuend), (subtrahend)) | ((borrowIn) & is_digit_zero_ct(tempReg)));  \
    (differenceOut) = tempReg - (digit_t)(borrowIn);                                              \
    (borrowOut) = borrowReg; }

/* Shift right with flexible datatype */
#define S2N_SIKE_P434_R3_SHIFTR(highIn, lowIn, shift, shiftOut, DigitSize)                        \
    (shiftOut) = ((lowIn) >> (shift)) ^ ((highIn) << ((DigitSize) - (shift)));

/* Fixed parameters for computation */
#define p434 S2N_SIKE_P434_R3_NAMESPACE(p434)
extern const uint64_t p434[S2N_SIKE_P434_R3_NWORDS64_FIELD];

#define p434x2 S2N_SIKE_P434_R3_NAMESPACE(p434x2)
extern const uint64_t p434x2[S2N_SIKE_P434_R3_NWORDS64_FIELD];

#define p434x4 S2N_SIKE_P434_R3_NAMESPACE(p434x4)
extern const uint64_t p434x4[S2N_SIKE_P434_R3_NWORDS64_FIELD];

#define p434p1 S2N_SIKE_P434_R3_NAMESPACE(p434p1)
extern const uint64_t p434p1[S2N_SIKE_P434_R3_NWORDS64_FIELD];

#define A_gen S2N_SIKE_P434_R3_NAMESPACE(A_gen)
extern const uint64_t A_gen[6*S2N_SIKE_P434_R3_NWORDS64_FIELD];

#define B_gen S2N_SIKE_P434_R3_NAMESPACE(B_gen)
extern const uint64_t B_gen[6*S2N_SIKE_P434_R3_NWORDS64_FIELD];

#define Montgomery_R2 S2N_SIKE_P434_R3_NAMESPACE(Montgomery_R2)
extern const uint64_t Montgomery_R2[S2N_SIKE_P434_R3_NWORDS64_FIELD];

#define Montgomery_one S2N_SIKE_P434_R3_NAMESPACE(Montgomery_one)
extern const uint64_t Montgomery_one[S2N_SIKE_P434_R3_NWORDS64_FIELD];

#define strat_Alice S2N_SIKE_P434_R3_NAMESPACE(strat_Alice)
extern const unsigned int strat_Alice[S2N_SIKE_P434_R3_MAX_ALICE-1];

#define strat_Bob S2N_SIKE_P434_R3_NAMESPACE(strat_Bob)
extern const unsigned int strat_Bob[S2N_SIKE_P434_R3_MAX_BOB-1];
