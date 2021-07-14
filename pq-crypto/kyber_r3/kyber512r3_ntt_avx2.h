#pragma once

#include <stdint.h>

#define ntt_avx2_asm S2N_KYBER_512_R3_NAMESPACE(ntt_avx2_asm)
void ntt_avx2_asm(int16_t *r, const int16_t *qdata);

#define invntt_avx2_asm S2N_KYBER_512_R3_NAMESPACE(invntt_avx2_asm)
void invntt_avx2_asm(int16_t *r, const int16_t *qdata);

#define nttunpack_avx2_asm S2N_KYBER_512_R3_NAMESPACE(nttunpack_avx2_asm)
void nttunpack_avx2_asm(int16_t *r, const int16_t *qdata);

#define basemul_avx2_asm S2N_KYBER_512_R3_NAMESPACE(basemul_avx2_asm)
void basemul_avx2_asm(int16_t *r,
                 const int16_t *a,
                 const int16_t *b,
                 const int16_t *qdata);

#define ntttobytes_avx2_asm S2N_KYBER_512_R3_NAMESPACE(ntttobytes_avx2_asm)
void ntttobytes_avx2_asm(uint8_t *r, const int16_t *a, const int16_t *qdata);

#define nttfrombytes_avx2_asm S2N_KYBER_512_R3_NAMESPACE(nttfrombytes_avx2_asm)
void nttfrombytes_avx2_asm(int16_t *r, const uint8_t *a, const int16_t *qdata);
