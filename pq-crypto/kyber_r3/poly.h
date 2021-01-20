#ifndef POLY_H
#define POLY_H

#include <stdint.h>
#include "params.h"

/*
 * Elements of R_q = Z_q[X]/(X^n + 1). Represents polynomial
 * coeffs[0] + X*coeffs[1] + X^2*xoeffs[2] + ... + X^{n-1}*coeffs[n-1]
 */
typedef struct{
  int16_t coeffs[KYBER_N];
} poly;

#define poly_compress KYBER_NAMESPACE(_poly_compress)
void poly_compress(uint8_t r[KYBER_POLYCOMPRESSEDBYTES], poly *a);
#define poly_decompress KYBER_NAMESPACE(_poly_decompress)
void poly_decompress(poly *r, const uint8_t a[KYBER_POLYCOMPRESSEDBYTES]);

#define poly_tobytes KYBER_NAMESPACE(_poly_tobytes)
void poly_tobytes(uint8_t r[KYBER_POLYBYTES], poly *a);
#define poly_frombytes KYBER_NAMESPACE(_poly_frombytes)
void poly_frombytes(poly *r, const uint8_t a[KYBER_POLYBYTES]);

#define poly_frommsg KYBER_NAMESPACE(_poly_frommsg)
void poly_frommsg(poly *r, const uint8_t msg[KYBER_INDCPA_MSGBYTES]);
#define poly_tomsg KYBER_NAMESPACE(_poly_tomsg)
void poly_tomsg(uint8_t msg[KYBER_INDCPA_MSGBYTES], poly *r);

#define poly_getnoise_eta1 KYBER_NAMESPACE(_poly_getnoise_eta1)
void poly_getnoise_eta1(poly *r, const uint8_t seed[KYBER_SYMBYTES], uint8_t nonce);

#define poly_getnoise_eta2 KYBER_NAMESPACE(_poly_getnoise_eta2)
void poly_getnoise_eta2(poly *r, const uint8_t seed[KYBER_SYMBYTES], uint8_t nonce);

#define poly_ntt KYBER_NAMESPACE(_poly_ntt)
void poly_ntt(poly *r);
#define poly_invntt_tomont KYBER_NAMESPACE(_poly_invntt_tomont)
void poly_invntt_tomont(poly *r);
#define poly_basemul_montgomery KYBER_NAMESPACE(_poly_basemul_montgomery)
void poly_basemul_montgomery(poly *r, const poly *a, const poly *b);
#define poly_tomont KYBER_NAMESPACE(_poly_tomont)
void poly_tomont(poly *r);

#define poly_reduce KYBER_NAMESPACE(_poly_reduce)
void poly_reduce(poly *r);
#define poly_csubq KYBER_NAMESPACE(_poly_csubq)
void poly_csubq(poly *r);

#define poly_add KYBER_NAMESPACE(_poly_add)
void poly_add(poly *r, const poly *a, const poly *b);
#define poly_sub KYBER_NAMESPACE(_poly_sub)
void poly_sub(poly *r, const poly *a, const poly *b);

#endif
