#pragma once

#include <stdint.h>

#if defined(S2N_KYBER512R3_AVX2_BMI2)
#include <immintrin.h>

#define ntt_avx2_asm S2N_KYBER_512_R3_NAMESPACE(ntt_avx2_asm)
void ntt_avx2_asm(__m256i *r, const __m256i *qdata);

#define invntt_avx2_asm S2N_KYBER_512_R3_NAMESPACE(invntt_avx2_asm)
void invntt_avx2_asm(__m256i *r, const __m256i *qdata);

#define nttunpack_avx2_asm S2N_KYBER_512_R3_NAMESPACE(nttunpack_avx2_asm)
void nttunpack_avx2_asm(__m256i *r, const __m256i *qdata);

#define basemul_avx2_asm S2N_KYBER_512_R3_NAMESPACE(basemul_avx2_asm)
void basemul_avx2_asm(__m256i *r,
                 const __m256i *a,
                 const __m256i *b,
                 const __m256i *qdata);

#define ntttobytes_avx2_asm S2N_KYBER_512_R3_NAMESPACE(ntttobytes_avx2_asm)
void ntttobytes_avx2_asm(uint8_t *r, const __m256i *a, const __m256i *qdata);

#define nttfrombytes_avx2_asm S2N_KYBER_512_R3_NAMESPACE(nttfrombytes_avx2_asm)
void nttfrombytes_avx2_asm(__m256i *r, const uint8_t *a, const __m256i *qdata);
#endif
