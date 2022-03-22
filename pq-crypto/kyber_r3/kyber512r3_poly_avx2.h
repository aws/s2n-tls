#pragma once

#include <stdint.h>
#include "kyber512r3_align_avx2.h"
#include "kyber512r3_params.h"

#if defined(S2N_KYBER512R3_AVX2_BMI2)
#define poly S2N_KYBER_512_R3_NAMESPACE(poly)
typedef ALIGNED_INT16(S2N_KYBER_512_R3_N) poly;

#define poly_compress_avx2 S2N_KYBER_512_R3_NAMESPACE(poly_compress_avx2)
void poly_compress_avx2(uint8_t r[S2N_KYBER_512_R3_POLYCOMPRESSEDBYTES], const poly *a);

#define poly_decompress_avx2 S2N_KYBER_512_R3_NAMESPACE(poly_decompress_avx2)
void poly_decompress_avx2(poly *r, const uint8_t a[S2N_KYBER_512_R3_POLYCOMPRESSEDBYTES]);

#define poly_tobytes_avx2 S2N_KYBER_512_R3_NAMESPACE(poly_tobytes_avx2)
void poly_tobytes_avx2(uint8_t r[S2N_KYBER_512_R3_POLYBYTES], const poly *a);

#define poly_frombytes_avx2 S2N_KYBER_512_R3_NAMESPACE(poly_frombytes_avx2)
void poly_frombytes_avx2(poly *r, const uint8_t a[S2N_KYBER_512_R3_POLYBYTES]);

#define poly_frommsg_avx2 S2N_KYBER_512_R3_NAMESPACE(poly_frommsg_avx2)
void poly_frommsg_avx2(poly *r, const uint8_t msg[S2N_KYBER_512_R3_INDCPA_MSGBYTES]);

#define poly_tomsg_avx2 S2N_KYBER_512_R3_NAMESPACE(poly_tomsg_avx2)
void poly_tomsg_avx2(uint8_t msg[S2N_KYBER_512_R3_INDCPA_MSGBYTES], const poly *r);

#define poly_getnoise_eta1_avx2 S2N_KYBER_512_R3_NAMESPACE(poly_getnoise_eta1_avx2)
void poly_getnoise_eta1_avx2(poly *r, const uint8_t seed[S2N_KYBER_512_R3_SYMBYTES], uint8_t nonce);

#define poly_getnoise_eta2_avx2 S2N_KYBER_512_R3_NAMESPACE(poly_getnoise_eta2_avx2)
void poly_getnoise_eta2_avx2(poly *r, const uint8_t seed[S2N_KYBER_512_R3_SYMBYTES], uint8_t nonce);

#define poly_getnoise_eta1_4x S2N_KYBER_512_R3_NAMESPACE(poly_getnoise_eta2_4x)
void poly_getnoise_eta1_4x(poly *r0,
                           poly *r1,
                           poly *r2,
                           poly *r3,
                           const uint8_t seed[32],
                           uint8_t nonce0,
                           uint8_t nonce1,
                           uint8_t nonce2,
                           uint8_t nonce3);

#define poly_getnoise_eta1122_4x S2N_KYBER_512_R3_NAMESPACE(poly_getnoise_eta1122_4x)
void poly_getnoise_eta1122_4x(poly *r0,
                              poly *r1,
                              poly *r2,
                              poly *r3,
                              const uint8_t seed[32],
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
#endif
