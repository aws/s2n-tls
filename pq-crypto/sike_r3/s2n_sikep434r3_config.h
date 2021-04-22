/********************************************************************************************
* Supersingular Isogeny Key Encapsulation Library
*
* Abstract: configuration file and platform-dependent macros
*********************************************************************************************/  

#pragma once

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

// Definition of operating system
#define OS_NIX       2
#define OS_TARGET OS_NIX

// Definition of compiler
#define COMPILER_GCC     2
#define COMPILER_CLANG   3

#if defined(__GNUC__)         // GNU GCC compiler
    #define COMPILER COMPILER_GCC   
#elif defined(__clang__)        // Clang compiler
    #define COMPILER COMPILER_CLANG
#else
    #error -- "Unsupported COMPILER"
#endif

// Definition of the targeted architecture and basic data types
#define TARGET_AMD64        1
#define TARGET_x86          2
#define TARGET_S390X        3
#define TARGET_ARM          4
#define TARGET_ARM64        5

#if defined(_AMD64_) || defined(__x86_64)
    #define TARGET TARGET_AMD64
    #define RADIX           64
    #define LOG2RADIX       6  
    typedef uint64_t        digit_t;        // Unsigned 64-bit digit
    typedef uint32_t        hdigit_t;       // Unsigned 32-bit digit
#elif defined(_X86_)
    #define TARGET TARGET_x86
    #define RADIX           32
    #define LOG2RADIX       5  
    typedef uint32_t        digit_t;        // Unsigned 32-bit digit
    typedef uint16_t        hdigit_t;       // Unsigned 16-bit digit  
#elif defined(_S390X_)
    #define TARGET TARGET_S390X
    #define RADIX           64
    #define LOG2RADIX       6  
    typedef uint64_t        digit_t;        // Unsigned 64-bit digit
    typedef uint32_t        hdigit_t;       // Unsigned 32-bit digit
#elif defined(_ARM_)
    #define TARGET TARGET_ARM
    #define RADIX           32
    #define LOG2RADIX       5  
    typedef uint32_t        digit_t;        // Unsigned 32-bit digit
    typedef uint16_t        hdigit_t;       // Unsigned 16-bit digit  
#elif defined(_ARM64_)
    #define TARGET TARGET_ARM64
    #define RADIX           64
    #define LOG2RADIX       6  
    typedef uint64_t        digit_t;        // Unsigned 64-bit digit
    typedef uint32_t        hdigit_t;       // Unsigned 32-bit digit
#else
    #error -- "Unsupported ARCHITECTURE"
#endif

// Macros for endianness
// 32-bit byte swap
#define BSWAP32(i) __builtin_bswap32((i))

// 64-bit byte swap
#define BSWAP64(i) __builtin_bswap64((i))

#if RADIX == 32
    #define BSWAP_DIGIT(i) BSWAP32((i))
#elif RADIX == 64
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
    return (unsigned int)((x | (0-x)) >> (RADIX-1));
}

static __inline unsigned int is_digit_zero_ct(const digit_t x)
{ // Is x = 0?
    return (unsigned int)(1 ^ is_digit_nonzero_ct(x));
}

static __inline unsigned int is_digit_lessthan_ct(const digit_t x, const digit_t y)
{ // Is x < y?
    return (unsigned int)((x ^ ((x ^ y) | ((x - y) ^ y))) >> (RADIX-1));
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
