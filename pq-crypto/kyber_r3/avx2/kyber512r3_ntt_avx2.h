#pragma once

#include <stdint.h>
#include <immintrin.h>

#define ntt_avx2_asm S2N_KYBER_512_R3_NAMESPACE(ntt_avx2_asm)
void ntt_avx2_asm(__m256i *r, const __m256i *kyber512_qdata_avx2);

#define invntt_avx_asm S2N_KYBER_512_R3_NAMESPACE(invntt_avx_asm)
void invntt_avx_asm(__m256i *r, const __m256i *kyber512_qdata_avx2);

#define nttunpack_avx2_asm S2N_KYBER_512_R3_NAMESPACE(nttunpack_avx2_asm)
void nttunpack_avx2_asm(__m256i *r, const __m256i *kyber512_qdata_avx2);

#define basemul_avx2_asm S2N_KYBER_512_R3_NAMESPACE(basemul_avx2_asm)
void basemul_avx2_asm(__m256i *r,
                                       const __m256i *a,
                                       const __m256i *b,
                                       const __m256i *kyber512_qdata_avx2);

#define ntttobytes_avx2_asm S2N_KYBER_512_R3_NAMESPACE(ntttobytes_avx2_asm)
void ntttobytes_avx2_asm(uint8_t *r, const __m256i *a, const __m256i *kyber512_qdata_avx2);

#define nttfrombytes_avx2_asm S2N_KYBER_512_R3_NAMESPACE(nttfrombytes_avx2_asm)
void nttfrombytes_avx2_asm(__m256i *r, const uint8_t *a, const __m256i *kyber512_qdata_avx2);

