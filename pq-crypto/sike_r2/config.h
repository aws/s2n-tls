/********************************************************************************************
* SIDH: an efficient supersingular isogeny cryptography library
*
* Abstract: configuration file and platform-dependent macros
*********************************************************************************************/

#ifndef SIKE_CONFIG_H
#define SIKE_CONFIG_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

// Definition of operating system

#define OS_WIN 1
#define OS_LINUX 2

#if defined(_WIN32) // Microsoft Windows OS
#define OS_TARGET OS_WIN
#else
#define OS_TARGET OS_LINUX // default to Linux
#endif

// Definition of compiler (removed in OQS)

#define COMPILER_GCC     1
#define COMPILER_CLANG   2

#if defined(__GNUC__)           // GNU GCC compiler
#define COMPILER COMPILER_GCC
#elif defined(__clang__)        // Clang compiler
#define COMPILER COMPILER_CLANG
#else
#error -- "Unsupported COMPILER"
#endif


// TODO - Hardcoding these #defines for now to get the build working with the generic C code.
//  Need to enable builds for multiple architectures, and enable/include optimized x64 assembly
//  code
#define _AMD64_
#define _GENERIC_

// Definition of the targeted architecture and basic data types

#define TARGET_AMD64 1
#define TARGET_x86 2
#define TARGET_ARM 3
#define TARGET_ARM64 4

#if defined(_AMD64_)
#define TARGET TARGET_AMD64
#define RADIX 64
#define LOG2RADIX 6
typedef uint64_t digit_t;  // Unsigned 64-bit digit
typedef uint32_t hdigit_t; // Unsigned 32-bit digit
#elif defined(_X86_)
#define TARGET TARGET_x86
#define RADIX 32
#define LOG2RADIX 5
typedef uint32_t digit_t;  // Unsigned 32-bit digit
typedef uint16_t hdigit_t; // Unsigned 16-bit digit
#elif defined(_ARM_)
#define TARGET TARGET_ARM
#define RADIX 32
#define LOG2RADIX 5
typedef uint32_t digit_t;  // Unsigned 32-bit digit
typedef uint16_t hdigit_t; // Unsigned 16-bit digit
#elif defined(_ARM64_)
#define TARGET TARGET_ARM64
#define RADIX 64
#define LOG2RADIX 6
typedef uint64_t digit_t;  // Unsigned 64-bit digit
typedef uint32_t hdigit_t; // Unsigned 32-bit digit
#else
#error-- "Unsupported ARCHITECTURE"
#endif

#define RADIX64 64

// Selection of generic, portable implementation

#if defined(_GENERIC_)
#define GENERIC_IMPLEMENTATION
#endif

// Extended datatype support
#if defined(GENERIC_IMPLEMENTATION)
typedef uint64_t uint128_t[2];
#elif (TARGET == TARGET_AMD64 && OS_TARGET == OS_LINUX)
typedef unsigned uint128_t __attribute__((mode(TI)));
#elif (TARGET == TARGET_ARM64 && OS_TARGET == OS_LINUX)
typedef unsigned uint128_t __attribute__((mode(TI)));
#elif (TARGET == TARGET_AMD64 && OS_TARGET == OS_WIN)
typedef uint64_t uint128_t[2];
#endif

// Macro definitions

#define NBITS_TO_NBYTES(nbits) (((nbits) + 7) / 8)                                             // Conversion macro from number of bits to number of bytes
#define NBITS_TO_NWORDS(nbits) (((nbits) + (sizeof(digit_t) * 8) - 1) / (sizeof(digit_t) * 8)) // Conversion macro from number of bits to number of computer words
#define NBYTES_TO_NWORDS(nbytes) (((nbytes) + sizeof(digit_t) - 1) / sizeof(digit_t))          // Conversion macro from number of bytes to number of computer words

// Macro to avoid compiler warnings when detecting unreferenced parameters
#define UNREFERENCED_PARAMETER(PAR) ((void) (PAR))

/********************** Constant-time unsigned comparisons ***********************/

// The following functions return 1 (TRUE) if condition is true, 0 (FALSE) otherwise

unsigned int is_digit_nonzero_ct(digit_t x) { // Is x != 0?
    return (unsigned int) ((x | (0 - x)) >> (RADIX - 1));
}

unsigned int is_digit_zero_ct(digit_t x) { // Is x = 0?
    return (unsigned int) (1 ^ is_digit_nonzero_ct(x));
}

unsigned int is_digit_lessthan_ct(digit_t x, digit_t y) { // Is x < y?
    return (unsigned int) ((x ^ ((x ^ y) | ((x - y) ^ y))) >> (RADIX - 1));
}

/********************** Macros for platform-dependent operations **********************/

#if defined(GENERIC_IMPLEMENTATION) || (TARGET == TARGET_ARM)

// Digit multiplication
#define MUL(multiplier, multiplicand, hi, lo) \
    digit_x_digit((multiplier), (multiplicand), &(lo));

// Digit addition with carry
#define ADDC(carryIn, addend1, addend2, carryOut, sumOut)                                                           \
    {                                                                                                               \
        digit_t tempReg = (addend1) + (digit_t)(carryIn);                                                           \
        (sumOut) = (addend2) + tempReg;                                                                             \
        (carryOut) = (is_digit_lessthan_ct(tempReg, (digit_t)(carryIn)) | is_digit_lessthan_ct((sumOut), tempReg)); \
    }

// Digit subtraction with borrow
#define SUBC(borrowIn, minuend, subtrahend, borrowOut, differenceOut)                                                       \
    {                                                                                                                       \
        digit_t tempReg = (minuend) - (subtrahend);                                                                         \
        unsigned int borrowReg = (is_digit_lessthan_ct((minuend), (subtrahend)) | ((borrowIn) &is_digit_zero_ct(tempReg))); \
        (differenceOut) = tempReg - (digit_t)(borrowIn);                                                                    \
        (borrowOut) = borrowReg;                                                                                            \
    }

// Shift right with flexible datatype
#define SHIFTR(highIn, lowIn, shift, shiftOut, DigitSize) \
    (shiftOut) = ((lowIn) >> (shift)) ^ ((highIn) << (DigitSize - (shift)));

// Shift left with flexible datatype
#define SHIFTL(highIn, lowIn, shift, shiftOut, DigitSize) \
    (shiftOut) = ((highIn) << (shift)) ^ ((lowIn) >> (DigitSize - (shift)));

#elif (TARGET == TARGET_AMD64 && OS_TARGET == OS_WIN)

// Digit multiplication
#define MUL(multiplier, multiplicand, hi, lo) \
    (lo) = _umul128((multiplier), (multiplicand), (hi));

// Digit addition with carry
#define ADDC(carryIn, addend1, addend2, carryOut, sumOut) \
    (carryOut) = _addcarry_u64((carryIn), (addend1), (addend2), &(sumOut));

// Digit subtraction with borrow
#define SUBC(borrowIn, minuend, subtrahend, borrowOut, differenceOut) \
    (borrowOut) = _subborrow_u64((borrowIn), (minuend), (subtrahend), &(differenceOut));

// Digit shift right
#define SHIFTR(highIn, lowIn, shift, shiftOut, DigitSize) \
    (shiftOut) = __shiftright128((lowIn), (highIn), (shift));

// Digit shift left
#define SHIFTL(highIn, lowIn, shift, shiftOut, DigitSize) \
    (shiftOut) = __shiftleft128((lowIn), (highIn), (shift));

// 64x64-bit multiplication
#define MUL128(multiplier, multiplicand, product) \
    (product)[0] = _umul128((multiplier), (multiplicand), &(product)[1]);

// 128-bit addition with output carry
#define ADC128(addend1, addend2, carry, addition)                           \
    (carry) = _addcarry_u64(0, (addend1)[0], (addend2)[0], &(addition)[0]); \
    (carry) = _addcarry_u64((carry), (addend1)[1], (addend2)[1], &(addition)[1]);

#define MULADD128(multiplier, multiplicand, addend, carry, result) \
    ;                                                              \
    {                                                              \
        uint128_t product;                                         \
        MUL128(multiplier, multiplicand, product);                 \
        ADC128(addend, product, carry, result);                    \
    }

#elif ((TARGET == TARGET_AMD64 || TARGET == TARGET_ARM64) && OS_TARGET == OS_LINUX)

// Digit multiplication
#define MUL(multiplier, multiplicand, hi, lo)                                    \
    {                                                                            \
        uint128_t tempReg = (uint128_t)(multiplier) * (uint128_t)(multiplicand); \
        *(hi) = (digit_t)(tempReg >> RADIX);                                     \
        (lo) = (digit_t) tempReg;                                                \
    }

// Digit addition with carry
#define ADDC(carryIn, addend1, addend2, carryOut, sumOut)                                       \
    {                                                                                           \
        uint128_t tempReg = (uint128_t)(addend1) + (uint128_t)(addend2) + (uint128_t)(carryIn); \
        (carryOut) = (digit_t)(tempReg >> RADIX);                                               \
        (sumOut) = (digit_t) tempReg;                                                           \
    }

// Digit subtraction with borrow
#define SUBC(borrowIn, minuend, subtrahend, borrowOut, differenceOut)                               \
    {                                                                                               \
        uint128_t tempReg = (uint128_t)(minuend) - (uint128_t)(subtrahend) - (uint128_t)(borrowIn); \
        (borrowOut) = (digit_t)(tempReg >> (sizeof(uint128_t) * 8 - 1));                            \
        (differenceOut) = (digit_t) tempReg;                                                        \
    }

// Digit shift right
#define SHIFTR(highIn, lowIn, shift, shiftOut, DigitSize) \
    (shiftOut) = ((lowIn) >> (shift)) ^ ((highIn) << (RADIX - (shift)));

// Digit shift left
#define SHIFTL(highIn, lowIn, shift, shiftOut, DigitSize) \
    (shiftOut) = ((highIn) << (shift)) ^ ((lowIn) >> (RADIX - (shift)));

#endif

#endif
