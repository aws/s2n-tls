#pragma once

#include <stdint.h>
#include "kyber512r3_params.h"
#include "kyber512r3_poly_avx2.h"

#if defined(S2N_KYBER512R3_AVX2_BMI2)
#define polyvec S2N_KYBER_512_R3_NAMESPACE(polyvec)
typedef struct{
  poly vec[S2N_KYBER_512_R3_K];
} polyvec;

#define polyvec_compress_avx2 S2N_KYBER_512_R3_NAMESPACE(polyvec_compress_avx2)
void polyvec_compress_avx2(uint8_t r[S2N_KYBER_512_R3_POLYVECCOMPRESSEDBYTES+2], const polyvec *a);

#define polyvec_decompress_avx2 S2N_KYBER_512_R3_NAMESPACE(polyvec_decompress_avx2)
void polyvec_decompress_avx2(polyvec *r, const uint8_t a[S2N_KYBER_512_R3_POLYVECCOMPRESSEDBYTES+12]);

#define polyvec_tobytes_avx2 S2N_KYBER_512_R3_NAMESPACE(polyvec_tobytes_avx2)
void polyvec_tobytes_avx2(uint8_t r[S2N_KYBER_512_R3_POLYVECBYTES], const polyvec *a);

#define polyvec_frombytes_avx2 S2N_KYBER_512_R3_NAMESPACE(polyvec_frombytes_avx2)
void polyvec_frombytes_avx2(polyvec *r, const uint8_t a[S2N_KYBER_512_R3_POLYVECBYTES]);

#define polyvec_ntt_avx2 S2N_KYBER_512_R3_NAMESPACE(polyvec_ntt_avx2)
void polyvec_ntt_avx2(polyvec *r);

#define polyvec_invntt_tomont_avx2 S2N_KYBER_512_R3_NAMESPACE(polyvec_invntt_tomont_avx2)
void polyvec_invntt_tomont_avx2(polyvec *r);

#define polyvec_basemul_acc_montgomery_avx2 S2N_KYBER_512_R3_NAMESPACE(polyvec_basemul_acc_montgomery_avx2)
void polyvec_basemul_acc_montgomery_avx2(poly *r, const polyvec *a, const polyvec *b);

#define polyvec_reduce_avx2 S2N_KYBER_512_R3_NAMESPACE(polyvec_reduce_avx2)
void polyvec_reduce_avx2(polyvec *r);

#define polyvec_add_avx2 S2N_KYBER_512_R3_NAMESPACE(polyvec_add_avx2)
void polyvec_add_avx2(polyvec *r, const polyvec *a, const polyvec *b);
#endif
