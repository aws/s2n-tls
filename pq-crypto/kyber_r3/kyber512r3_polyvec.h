#pragma once

#include <stdint.h>
#include "kyber512r3_params.h"
#include "kyber512r3_poly.h"

#define polyvec S2N_KYBER_512_R3_NAMESPACE(polyvec)
typedef struct {
    poly vec[S2N_KYBER_512_R3_K];
} polyvec;

#define polyvec_compress S2N_KYBER_512_R3_NAMESPACE(polyvec_compress)
void polyvec_compress(uint8_t r[S2N_KYBER_512_R3_POLYVECCOMPRESSEDBYTES], polyvec *a);

#define polyvec_decompress S2N_KYBER_512_R3_NAMESPACE(polyvec_decompress)
void polyvec_decompress(polyvec *r, const uint8_t a[S2N_KYBER_512_R3_POLYVECCOMPRESSEDBYTES]);

#define polyvec_tobytes S2N_KYBER_512_R3_NAMESPACE(polyvec_tobytes)
void polyvec_tobytes(uint8_t r[S2N_KYBER_512_R3_POLYVECBYTES], polyvec *a);

#define polyvec_frombytes S2N_KYBER_512_R3_NAMESPACE(polyvec_frombytes)
void polyvec_frombytes(polyvec *r, const uint8_t a[S2N_KYBER_512_R3_POLYVECBYTES]);

#define polyvec_ntt S2N_KYBER_512_R3_NAMESPACE(polyvec_ntt)
void polyvec_ntt(polyvec *r);

#define polyvec_invntt_tomont S2N_KYBER_512_R3_NAMESPACE(polyvec_invntt_tomont)
void polyvec_invntt_tomont(polyvec *r);

#define polyvec_pointwise_acc_montgomery S2N_KYBER_512_R3_NAMESPACE(polyvec_pointwise_acc_montgomery)
void polyvec_pointwise_acc_montgomery(poly *r, const polyvec *a, const polyvec *b);

#define polyvec_reduce S2N_KYBER_512_R3_NAMESPACE(polyvec_reduce)
void polyvec_reduce(polyvec *r);

#define polyvec_csubq S2N_KYBER_512_R3_NAMESPACE(polyvec_csubq)
void polyvec_csubq(polyvec *r);

#define polyvec_add S2N_KYBER_512_R3_NAMESPACE(polyvec_add)
void polyvec_add(polyvec *r, const polyvec *a, const polyvec *b);
