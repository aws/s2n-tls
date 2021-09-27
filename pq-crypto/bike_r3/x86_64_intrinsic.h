/* Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0"
 *
 * Written by Nir Drucker, Shay Gueron and Dusan Kostic,
 * AWS Cryptographic Algorithms Group.
 */

// This file contains definitions of macros for SIMD intrinsic functions, used
// throughout the code package. Where necessary, we add a suffix to a macro,
// and denote the type of the elements (operateds). For example,
//   - I16 denotes 16-bit wide integers,
//   - U64 denotes 64-bit wide unsigned integers.

#pragma once

#if defined(S2N_BIKE_R3_AVX2) || defined(S2N_BIKE_R3_AVX512)
#  include <immintrin.h>
#endif

// clang 3.9 doesn't recognize this macro
#if !defined(_MM_CMPINT_EQ)
#  define _MM_CMPINT_EQ (0)
#endif

// For functions in gf2x_mul.c we use exactly the same code for
// PORTABLE, AVX2, AVX512 implementations. Based on the implementation,
// we define macros for the different data types (uint64_t, __m256i, __m512i),
// and all the required operations (LOAD, STORE, >>, <<) on these types.
#if defined(AVX2_INTERNAL)

#  define REG_T __m256i

#  define LOAD(mem)       _mm256_loadu_si256((const void *)(mem))
#  define STORE(mem, reg) _mm256_storeu_si256((void *)(mem), (reg))

#  define SLLI_I64(a, imm) _mm256_slli_epi64(a, imm)
#  define SRLI_I64(a, imm) _mm256_srli_epi64(a, imm)

#elif defined(AVX512_INTERNAL)

#  define REG_T __m512i

#  define LOAD(mem)       _mm512_loadu_si512((mem))
#  define STORE(mem, reg) _mm512_storeu_si512((mem), (reg))

#  define SLLI_I64(a, imm) _mm512_slli_epi64(a, imm)
#  define SRLI_I64(a, imm) _mm512_srli_epi64(a, imm)

#elif defined(PORTABLE_INTERNAL)

#  define REG_T uint64_t

#  define LOAD(mem)       (mem)[0]
#  define STORE(mem, val) (mem)[0] = val

#  define SLLI_I64(a, imm) ((a) << (imm))
#  define SRLI_I64(a, imm) ((a) >> (imm))

#endif

// NOLINT is used to avoid the sizeof(T)/sizeof(T) warning when REG_T is defined
// to be uint64_t
#define REG_QWORDS (sizeof(REG_T) / sizeof(uint64_t)) // NOLINT
#define REG_DWORDS (sizeof(REG_T) / sizeof(uint32_t)) // NOLINT

// The rest of the SIMD macros that are
// required for AVX2 and AVX512 implementation.
#if defined(AVX2_INTERNAL)

#  define SET_I8(...)  _mm256_set_epi8(__VA_ARGS__)
#  define SET_I32(...) _mm256_set_epi32(__VA_ARGS__)
#  define SET_I64(...) _mm256_set_epi64x(__VA_ARGS__)
#  define SET1_I8(a)   _mm256_set1_epi8(a)
#  define SET1_I16(a)  _mm256_set1_epi16(a)
#  define SET1_I32(a)  _mm256_set1_epi32(a)
#  define SET1_I64(a)  _mm256_set1_epi64x(a)
#  define SET_ZERO     _mm256_setzero_si256()

#  define ADD_I8(a, b)     _mm256_add_epi8(a, b)
#  define SUB_I8(a, b)     _mm256_sub_epi8(a, b)
#  define ADD_I16(a, b)    _mm256_add_epi16(a, b)
#  define SUB_I16(a, b)    _mm256_sub_epi16(a, b)
#  define ADD_I64(a, b)    _mm256_add_epi64(a, b)
#  define SRLI_I16(a, imm) _mm256_srli_epi16(a, imm)
#  define SLLI_I32(a, imm) _mm256_slli_epi32(a, imm)
#  define SLLV_I32(a, b)   _mm256_sllv_epi32(a, b)

#  define CMPGT_I16(a, b) _mm256_cmpgt_epi16(a, b)
#  define CMPEQ_I16(a, b) _mm256_cmpeq_epi16(a, b)
#  define CMPEQ_I32(a, b) _mm256_cmpeq_epi32(a, b)
#  define CMPEQ_I64(a, b) _mm256_cmpeq_epi64(a, b)

#  define SHUF_I8(a, b)         _mm256_shuffle_epi8(a, b)
#  define BLENDV_I8(a, b, mask) _mm256_blendv_epi8(a, b, mask)
#  define PERMVAR_I32(a, idx)   _mm256_permutevar8x32_epi32(a, idx)
#  define PERM_I64(a, imm)      _mm256_permute4x64_epi64(a, imm)

#  define MOVEMASK(a) _mm256_movemask_epi8(a)

#elif defined(AVX512_INTERNAL)

#  define MSTORE(mem, mask, reg) _mm512_mask_store_epi64((mem), (mask), (reg))

#  define SET1_I8(a)         _mm512_set1_epi8(a)
#  define SET1_I32(a)        _mm512_set1_epi32(a)
#  define SET1_I64(a)        _mm512_set1_epi64(a)
#  define SET1MZ_I8(mask, a) _mm512_maskz_set1_epi8(mask, a)
#  define SET1_I16(a)        _mm512_set1_epi16(a)
#  define SET_I64(...)       _mm512_set_epi64(__VA_ARGS__)
#  define SET_ZERO           _mm512_setzero_si512()

#  define ADD_I16(a, b)             _mm512_add_epi16(a, b)
#  define ADD_I64(a, b)             _mm512_add_epi64(a, b)
#  define MSUB_I16(src, k, a, b)    _mm512_mask_sub_epi16(src, k, a, b)
#  define SRLI_I16(a, imm)          _mm512_srli_epi16(a, imm)
#  define SRLV_I64(a, cnt)          _mm512_srlv_epi64(a, cnt)
#  define SLLV_I64(a, cnt)          _mm512_sllv_epi64(a, cnt)
#  define MOR_I64(src, mask, a, b)  _mm512_mask_or_epi64(src, mask, a, b)
#  define MXOR_I64(src, mask, a, b) _mm512_mask_xor_epi64(src, mask, a, b)
#  define VALIGN(a, b, count)       _mm512_alignr_epi64(a, b, count)

#  define CMPM_U8(a, b, cmp_op)  _mm512_cmp_epu8_mask(a, b, cmp_op)
#  define CMPM_U16(a, b, cmp_op) _mm512_cmp_epu16_mask(a, b, cmp_op)
#  define CMPMEQ_I64(a, b)       _mm512_cmp_epi64_mask(a, b, _MM_CMPINT_EQ)
#  define MCMPMEQ_I32(mask, a, b) \
    _mm512_mask_cmp_epi32_mask(mask, a, b, _MM_CMPINT_EQ)

#  define PERMX_I64(a, imm)        _mm512_permutex_epi64(a, imm)
#  define PERMX2VAR_I64(a, idx, b) _mm512_permutex2var_epi64(a, idx, b)
#  define PERMXVAR_I64(idx, a)     _mm512_permutexvar_epi64(idx, a)

#endif
