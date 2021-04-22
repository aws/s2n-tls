/********************************************************************************************
* Supersingular Isogeny Key Encapsulation Library
*
* Abstract: configuration file and platform-dependent macros
*********************************************************************************************/  

#pragma once

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#if defined(_AMD64_) || defined(__x86_64) || defined(_S390X_) || defined(_ARM64_) || defined(__powerpc64__) || (defined(__riscv) && (__riscv_xlen == 64))
    #define S2N_SIKE_P434_R3_NWORDS_FIELD 7 /* Number of words of a 434-bit field element */
    #define S2N_SIKE_P434_R3_ZERO_WORDS 3 /* Number of "0" digits in the least significant part of p434 + 1 */
    #define S2N_SIKE_P434_R3_RADIX 64
    #define S2N_SIKE_P434_R3_LOG2RADIX 6
    typedef uint64_t digit_t;
    typedef uint32_t hdigit_t;
#elif defined(_X86_) || defined(_ARM_)
    #define S2N_SIKE_P434_R3_NWORDS_FIELD 14 /* Number of words of a 434-bit field element */
    #define S2N_SIKE_P434_R3_ZERO_WORDS 6 /* Number of "0" digits in the least significant part of p434 + 1 */
    #define S2N_SIKE_P434_R3_RADIX 32
    #define S2N_SIKE_P434_R3_LOG2RADIX 5
    typedef uint32_t digit_t;
    typedef uint16_t hdigit_t;
#else
    #error -- "Unsupported ARCHITECTURE"
#endif

// Macros for endianness
// 32-bit byte swap
#define BSWAP32(i) __builtin_bswap32((i))

// 64-bit byte swap
#define BSWAP64(i) __builtin_bswap64((i))

#if S2N_SIKE_P434_R3_RADIX == 32
    #define BSWAP_DIGIT(i) BSWAP32((i))
#elif S2N_SIKE_P434_R3_RADIX == 64
    #define BSWAP_DIGIT(i) BSWAP64((i))
#endif

// Host to little endian, little endian to host
#if defined(__BYTE_ORDER__) && (__BYTE_ORDER__ == __ORDER_BIG_ENDIAN__)
    #define _BIG_ENDIAN_
    #define HTOLE_64(i) BSWAP64((i))
    #define LETOH_64(i) BSWAP64((i))
#else
    #define _LITTLE_ENDIAN_
    #define HTOLE_64(i) (i)
    #define LETOH_64(i) (i)
#endif

/********************** Constant-time unsigned comparisons ***********************/

// The following functions return 1 (TRUE) if condition is true, 0 (FALSE) otherwise

static __inline unsigned int is_digit_nonzero_ct(const digit_t x)
{ // Is x != 0?
    return (unsigned int)((x | (0-x)) >> (S2N_SIKE_P434_R3_RADIX-1));
}

static __inline unsigned int is_digit_zero_ct(const digit_t x)
{ // Is x = 0?
    return (unsigned int)(1 ^ is_digit_nonzero_ct(x));
}

static __inline unsigned int is_digit_lessthan_ct(const digit_t x, const digit_t y)
{ // Is x < y?
    return (unsigned int)((x ^ ((x ^ y) | ((x - y) ^ y))) >> (S2N_SIKE_P434_R3_RADIX-1));
}

/* Definitions for generic C implementation */

typedef uint64_t uint128_t[2];

// Digit multiplication
#define MUL(multiplier, multiplicand, hi, lo)                                                     \
    digit_x_digit((multiplier), (multiplicand), &(lo));

// Digit addition with carry
#define ADDC(carryIn, addend1, addend2, carryOut, sumOut)                                         \
    { digit_t tempReg = (addend1) + (digit_t)(carryIn);                                           \
    (sumOut) = (addend2) + tempReg;                                                               \
    (carryOut) = (is_digit_lessthan_ct(tempReg, (digit_t)(carryIn)) | is_digit_lessthan_ct((sumOut), tempReg)); }

// Digit subtraction with borrow
#define SUBC(borrowIn, minuend, subtrahend, borrowOut, differenceOut)                             \
    { digit_t tempReg = (minuend) - (subtrahend);                                                 \
    unsigned int borrowReg = (is_digit_lessthan_ct((minuend), (subtrahend)) | ((borrowIn) & is_digit_zero_ct(tempReg)));  \
    (differenceOut) = tempReg - (digit_t)(borrowIn);                                              \
    (borrowOut) = borrowReg; }

// Shift right with flexible datatype
#define SHIFTR(highIn, lowIn, shift, shiftOut, DigitSize)                                         \
    (shiftOut) = ((lowIn) >> (shift)) ^ ((highIn) << ((DigitSize) - (shift)));

// Shift left with flexible datatype
#define SHIFTL(highIn, lowIn, shift, shiftOut, DigitSize)                                         \
    (shiftOut) = ((highIn) << (shift)) ^ ((lowIn) >> ((DigitSize) - (shift)));
