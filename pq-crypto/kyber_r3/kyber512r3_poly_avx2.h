#pragma once

#include <stdint.h>
#include "kyber512r3_params.h"

/*
 * Elements of R_q = Z_q[X]/(X^n + 1). Represents polynomial
 * coeffs[0] + X*coeffs[1] + X^2*xoeffs[2] + ... + X^{n-1}*coeffs[n-1]
 */
#define poly S2N_KYBER_512_R3_NAMESPACE(poly)
typedef struct{
  int16_t coeffs[S2N_KYBER_512_R3_N] __attribute__((aligned(32)));
} poly;

#define poly_compress_avx2 S2N_KYBER_512_R3_NAMESPACE(poly_compress_avx2)
void poly_compress_avx2(uint8_t r[S2N_KYBER_512_R3_POLYCOMPRESSEDBYTES], const poly *a);

#define poly_decompress_avx2 S2N_KYBER_512_R3_NAMESPACE(poly_decompress_avx2)
void poly_decompress_avx2(poly *r, const uint8_t a[S2N_KYBER_512_R3_POLYCOMPRESSEDBYTES+6]);

#define poly_tobytes_avx2 S2N_KYBER_512_R3_NAMESPACE(poly_tobytes_avx2)
void poly_tobytes_avx2(uint8_t r[S2N_KYBER_512_R3_POLYBYTES], poly *a);

#define poly_frombytes_avx2 S2N_KYBER_512_R3_NAMESPACE(poly_frombytes_avx2)
void poly_frombytes_avx2(poly *r, const uint8_t a[S2N_KYBER_512_R3_POLYBYTES]);

#define poly_frommsg_avx2 S2N_KYBER_512_R3_NAMESPACE(poly_frommsg_avx2)
void poly_frommsg_avx2(poly *r, const uint8_t msg[S2N_KYBER_512_R3_INDCPA_MSGBYTES]);

#define poly_tomsg_avx2 S2N_KYBER_512_R3_NAMESPACE(poly_tomsg_avx2)
void poly_tomsg_avx2(uint8_t msg[S2N_KYBER_512_R3_INDCPA_MSGBYTES], poly *r);

#define poly_getnoise_eta2_avx2 S2N_KYBER_512_R3_NAMESPACE(poly_getnoise_eta2_avx2)
void poly_getnoise_eta2_avx2(poly *r, const uint8_t seed[S2N_KYBER_512_R3_SYMBYTES], uint8_t nonce);

#define poly_getnoise_eta1_4x S2N_KYBER_512_R3_NAMESPACE(_poly_getnoise_eta1_4x)
void poly_getnoise_eta1_4x(poly *r0,
                     poly *r1,
                     poly *r2,
                     poly *r3,
                     const uint8_t *seed,
                     uint8_t nonce0,
                     uint8_t nonce1,
                     uint8_t nonce2,
                     uint8_t nonce3);

#define poly_getnoise_eta1122_4x S2N_KYBER_512_R3_NAMESPACE(poly_getnoise_eta1122_4x)
void poly_getnoise_eta1122_4x(poly *r0,
                     poly *r1,
                     poly *r2,
                     poly *r3,
                     const uint8_t *seed,
                     uint8_t nonce0,
                     uint8_t nonce1,
                     uint8_t nonce2,
                     uint8_t nonce3);

#define poly_ntt_avx2 S2N_KYBER_512_R3_NAMESPACE(poly_ntt_avx2)
void poly_ntt_avx2(poly *r);

#define poly_invntt_tomont_avx2 S2N_KYBER_512_R3_NAMESPACE(poly_invntt_tomont_avx2)
void poly_invntt_tomont_avx2(poly *r);

#define poly_nttunpack_avx2 S2N_KYBER_512_R3_NAMESPACE(poly_nttunpack_avx2)
void poly_nttunpack_avx2(poly *r);

#define poly_basemul_montgomery_avx2 S2N_KYBER_512_R3_NAMESPACE(poly_basemul_montgomery_avx2)
void poly_basemul_montgomery_avx2(poly *r, const poly *a, const poly *b);

#define poly_tomont_avx2 S2N_KYBER_512_R3_NAMESPACE(poly_tomont_avx2)
void poly_tomont_avx2(poly *r);

#define poly_reduce_avx2 S2N_KYBER_512_R3_NAMESPACE(poly_reduce_avx2)
void poly_reduce_avx2(poly *r);

#define poly_add_avx2 S2N_KYBER_512_R3_NAMESPACE(poly_add_avx2)
void poly_add_avx2(poly *r, const poly *a, const poly *b);

#define poly_sub_avx2 S2N_KYBER_512_R3_NAMESPACE(poly_sub_avx2)
void poly_sub_avx2(poly *r, const poly *a, const poly *b);
