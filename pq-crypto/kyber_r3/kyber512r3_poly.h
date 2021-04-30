#pragma once

#include <stdint.h>
#include "kyber512r3_params.h"

/*
 * Elements of R_q = Z_q[X]/(X^n + 1). Represents polynomial
 * coeffs[0] + X*coeffs[1] + X^2*xoeffs[2] + ... + X^{n-1}*coeffs[n-1]
 */
#define poly S2N_KYBER_512_R3_NAMESPACE(poly)
typedef struct {
    int16_t coeffs[S2N_KYBER_512_R3_N];
} poly;

#define poly_compress S2N_KYBER_512_R3_NAMESPACE(poly_compress)
void poly_compress(uint8_t r[S2N_KYBER_512_R3_POLYCOMPRESSEDBYTES], poly *a);

#define poly_decompress S2N_KYBER_512_R3_NAMESPACE(poly_decompress)
void poly_decompress(poly *r, const uint8_t a[S2N_KYBER_512_R3_POLYCOMPRESSEDBYTES]);

#define poly_tobytes S2N_KYBER_512_R3_NAMESPACE(poly_tobytes)
void poly_tobytes(uint8_t r[S2N_KYBER_512_R3_POLYBYTES], poly *a);

#define poly_frombytes S2N_KYBER_512_R3_NAMESPACE(poly_frombytes)
void poly_frombytes(poly *r, const uint8_t a[S2N_KYBER_512_R3_POLYBYTES]);

#define poly_frommsg S2N_KYBER_512_R3_NAMESPACE(poly_frommsg)
void poly_frommsg(poly *r, const uint8_t msg[S2N_KYBER_512_R3_INDCPA_MSGBYTES]);

#define poly_tomsg S2N_KYBER_512_R3_NAMESPACE(poly_tomsg)
void poly_tomsg(uint8_t msg[S2N_KYBER_512_R3_INDCPA_MSGBYTES], poly *r);

#define poly_getnoise_eta1 S2N_KYBER_512_R3_NAMESPACE(poly_getnoise_eta1)
void poly_getnoise_eta1(poly *r, const uint8_t seed[S2N_KYBER_512_R3_SYMBYTES], uint8_t nonce);

#define poly_getnoise_eta2 S2N_KYBER_512_R3_NAMESPACE(poly_getnoise_eta2)
void poly_getnoise_eta2(poly *r, const uint8_t seed[S2N_KYBER_512_R3_SYMBYTES], uint8_t nonce);

#define poly_ntt S2N_KYBER_512_R3_NAMESPACE(poly_ntt)
void poly_ntt(poly *r);

#define poly_invntt_tomont S2N_KYBER_512_R3_NAMESPACE(poly_invntt_tomont)
void poly_invntt_tomont(poly *r);

#define poly_basemul_montgomery S2N_KYBER_512_R3_NAMESPACE(poly_basemul_montgomery)
void poly_basemul_montgomery(poly *r, const poly *a, const poly *b);

#define poly_tomont S2N_KYBER_512_R3_NAMESPACE(poly_tomont)
void poly_tomont(poly *r);

#define poly_reduce S2N_KYBER_512_R3_NAMESPACE(poly_reduce)
void poly_reduce(poly *r);

#define poly_csubq S2N_KYBER_512_R3_NAMESPACE(poly_csubq)
void poly_csubq(poly *r);

#define poly_add S2N_KYBER_512_R3_NAMESPACE(poly_add)
void poly_add(poly *r, const poly *a, const poly *b);

#define poly_sub S2N_KYBER_512_R3_NAMESPACE(poly_sub)
void poly_sub(poly *r, const poly *a, const poly *b);
