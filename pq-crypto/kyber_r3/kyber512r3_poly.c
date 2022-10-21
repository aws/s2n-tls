#include <stdint.h>
#include "kyber512r3_params.h"
#include "kyber512r3_poly.h"
#include "kyber512r3_ntt.h"
#include "kyber512r3_reduce.h"
#include "kyber512r3_cbd.h"
#include "kyber512r3_symmetric.h"

S2N_ENSURE_PORTABLE_OPTIMIZATIONS

/*************************************************
* Name:        poly_compress
*
* Description: Compression and subsequent serialization of a polynomial
*
* Arguments:   - uint8_t *r: pointer to output byte array
*                            (of length S2N_KYBER_512_R3_POLYCOMPRESSEDBYTES)
*              - poly *a:    pointer to input polynomial
**************************************************/
void poly_compress(uint8_t r[S2N_KYBER_512_R3_POLYCOMPRESSEDBYTES], poly *a) {
    unsigned int i, j;
    uint8_t t[8];

    poly_csubq(a);

    for (i = 0; i < S2N_KYBER_512_R3_N / 8; i++) {
        for (j = 0; j < 8; j++) {
            t[j] = ((((uint16_t)a->coeffs[8 * i + j] << 4) + S2N_KYBER_512_R3_Q / 2) / S2N_KYBER_512_R3_Q) & 15;
        }

        r[0] = t[0] | (t[1] << 4);
        r[1] = t[2] | (t[3] << 4);
        r[2] = t[4] | (t[5] << 4);
        r[3] = t[6] | (t[7] << 4);
        r += 4;
    }
}

/*************************************************
* Name:        poly_decompress
*
* Description: De-serialization and subsequent decompression of a polynomial;
*              approximate inverse of poly_compress
*
* Arguments:   - poly *r:          pointer to output polynomial
*              - const uint8_t *a: pointer to input byte array
*                                  (of length S2N_KYBER_512_R3_POLYCOMPRESSEDBYTES bytes)
**************************************************/
void poly_decompress(poly *r, const uint8_t a[S2N_KYBER_512_R3_POLYCOMPRESSEDBYTES]) {
    unsigned int i;

    for (i = 0; i < S2N_KYBER_512_R3_N / 2; i++) {
        r->coeffs[2 * i + 0] = (((uint16_t)(a[0] & 15) * S2N_KYBER_512_R3_Q) + 8) >> 4;
        r->coeffs[2 * i + 1] = (((uint16_t)(a[0] >> 4) * S2N_KYBER_512_R3_Q) + 8) >> 4;
        a += 1;
    }
}

/*************************************************
* Name:        poly_tobytes
*
* Description: Serialization of a polynomial
*
* Arguments:   - uint8_t *r: pointer to output byte array
*                            (needs space for S2N_KYBER_512_R3_POLYBYTES bytes)
*              - poly *a:    pointer to input polynomial
**************************************************/
void poly_tobytes(uint8_t r[S2N_KYBER_512_R3_POLYBYTES], poly *a) {
    unsigned int i;

    poly_csubq(a);

    for (i = 0; i < S2N_KYBER_512_R3_N / 2; i++) {
        uint16_t t0 = a->coeffs[2 * i];
        uint16_t t1 = a->coeffs[2 * i + 1];
        r[3 * i + 0] = (t0 >> 0);
        r[3 * i + 1] = (t0 >> 8) | (t1 << 4);
        r[3 * i + 2] = (t1 >> 4);
    }
}

/*************************************************
* Name:        poly_frombytes
*
* Description: De-serialization of a polynomial;
*              inverse of poly_tobytes
*
* Arguments:   - poly *r:          pointer to output polynomial
*              - const uint8_t *a: pointer to input byte array
*                                  (of S2N_KYBER_512_R3_POLYBYTES bytes)
**************************************************/
void poly_frombytes(poly *r, const uint8_t a[S2N_KYBER_512_R3_POLYBYTES]) {
    unsigned int i;
    for (i = 0; i < S2N_KYBER_512_R3_N / 2; i++) {
        r->coeffs[2 * i]   = ((a[3 * i + 0] >> 0) | ((uint16_t)a[3 * i + 1] << 8)) & 0xFFF;
        r->coeffs[2 * i + 1] = ((a[3 * i + 1] >> 4) | ((uint16_t)a[3 * i + 2] << 4)) & 0xFFF;
    }
}

/*************************************************
* Name:        poly_frommsg
*
* Description: Convert 32-byte message to polynomial
*
* Arguments:   - poly *r:            pointer to output polynomial
*              - const uint8_t *msg: pointer to input message
**************************************************/
void poly_frommsg(poly *r, const uint8_t msg[S2N_KYBER_512_R3_INDCPA_MSGBYTES]) {
    unsigned int i, j;
    int16_t mask;

    for (i = 0; i < S2N_KYBER_512_R3_N / 8; i++) {
        for (j = 0; j < 8; j++) {
            mask = -(int16_t)((msg[i] >> j) & 1);
            r->coeffs[8 * i + j] = mask & ((S2N_KYBER_512_R3_Q + 1) / 2);
        }
    }
}

/*************************************************
* Name:        poly_tomsg
*
* Description: Convert polynomial to 32-byte message
*
* Arguments:   - uint8_t *msg: pointer to output message
*              - poly *a:      pointer to input polynomial
**************************************************/
void poly_tomsg(uint8_t msg[S2N_KYBER_512_R3_INDCPA_MSGBYTES], poly *a) {
    unsigned int i, j;
    uint16_t t;

    poly_csubq(a);

    for (i = 0; i < S2N_KYBER_512_R3_N / 8; i++) {
        msg[i] = 0;
        for (j = 0; j < 8; j++) {
            t = ((((uint16_t)a->coeffs[8 * i + j] << 1) + S2N_KYBER_512_R3_Q / 2) / S2N_KYBER_512_R3_Q) & 1;
            msg[i] |= t << j;
        }
    }
}

/*************************************************
* Name:        poly_getnoise_eta1
*
* Description: Sample a polynomial deterministically from a seed and a nonce,
*              with output polynomial close to centered binomial distribution
*              with parameter S2N_KYBER_512_R3_ETA1
*
* Arguments:   - poly *r:             pointer to output polynomial
*              - const uint8_t *seed: pointer to input seed
*                                     (of length S2N_KYBER_512_R3_SYMBYTES bytes)
*              - uint8_t nonce:       one-byte input nonce
**************************************************/
void poly_getnoise_eta1(poly *r, const uint8_t seed[S2N_KYBER_512_R3_SYMBYTES], uint8_t nonce) {
    uint8_t buf[S2N_KYBER_512_R3_ETA1 * S2N_KYBER_512_R3_N / 4];
    shake256_prf(buf, sizeof(buf), seed, nonce);
    cbd_eta1(r, buf);
}

/*************************************************
* Name:        poly_getnoise_eta2
*
* Description: Sample a polynomial deterministically from a seed and a nonce,
*              with output polynomial close to centered binomial distribution
*              with parameter S2N_KYBER_512_R3_ETA2
*
* Arguments:   - poly *r:             pointer to output polynomial
*              - const uint8_t *seed: pointer to input seed
*                                     (of length S2N_KYBER_512_R3_SYMBYTES bytes)
*              - uint8_t nonce:       one-byte input nonce
**************************************************/
void poly_getnoise_eta2(poly *r, const uint8_t seed[S2N_KYBER_512_R3_SYMBYTES], uint8_t nonce) {
    uint8_t buf[S2N_KYBER_512_R3_ETA2 * S2N_KYBER_512_R3_N / 4];
    shake256_prf(buf, sizeof(buf), seed, nonce);
    cbd_eta2(r, buf);
}


/*************************************************
* Name:        poly_ntt
*
* Description: Computes negacyclic number-theoretic transform (NTT) of
*              a polynomial in place;
*              inputs assumed to be in normal order, output in bitreversed order
*
* Arguments:   - uint16_t *r: pointer to in/output polynomial
**************************************************/
void poly_ntt(poly *r) {
    ntt(r->coeffs);
    poly_reduce(r);
}

/*************************************************
* Name:        poly_invntt_tomont
*
* Description: Computes inverse of negacyclic number-theoretic transform (NTT)
*              of a polynomial in place;
*              inputs assumed to be in bitreversed order, output in normal order
*
* Arguments:   - uint16_t *a: pointer to in/output polynomial
**************************************************/
void poly_invntt_tomont(poly *r) {
    invntt(r->coeffs);
}

/*************************************************
* Name:        poly_basemul_montgomery
*
* Description: Multiplication of two polynomials in NTT domain
*
* Arguments:   - poly *r:       pointer to output polynomial
*              - const poly *a: pointer to first input polynomial
*              - const poly *b: pointer to second input polynomial
**************************************************/
void poly_basemul_montgomery(poly *r, const poly *a, const poly *b) {
    unsigned int i;
    for (i = 0; i < S2N_KYBER_512_R3_N / 4; i++) {
        basemul(&r->coeffs[4 * i], &a->coeffs[4 * i], &b->coeffs[4 * i], zetas[64 + i]);
        basemul(&r->coeffs[4 * i + 2], &a->coeffs[4 * i + 2], &b->coeffs[4 * i + 2],
                -zetas[64 + i]);
    }
}

/*************************************************
* Name:        poly_tomont
*
* Description: Inplace conversion of all coefficients of a polynomial
*              from normal domain to Montgomery domain
*
* Arguments:   - poly *r: pointer to input/output polynomial
**************************************************/
void poly_tomont(poly *r) {
    unsigned int i;
    const int16_t f = (1ULL << 32) % S2N_KYBER_512_R3_Q;
    for (i = 0; i < S2N_KYBER_512_R3_N; i++) {
        r->coeffs[i] = montgomery_reduce((int32_t)r->coeffs[i] * f);
    }
}

/*************************************************
* Name:        poly_reduce
*
* Description: Applies Barrett reduction to all coefficients of a polynomial
*              for details of the Barrett reduction see comments in reduce.c
*
* Arguments:   - poly *r: pointer to input/output polynomial
**************************************************/
void poly_reduce(poly *r) {
    unsigned int i;
    for (i = 0; i < S2N_KYBER_512_R3_N; i++) {
        r->coeffs[i] = barrett_reduce(r->coeffs[i]);
    }
}

/*************************************************
* Name:        poly_csubq
*
* Description: Applies conditional subtraction of q to each coefficient
*              of a polynomial. For details of conditional subtraction
*              of q see comments in reduce.c
*
* Arguments:   - poly *r: pointer to input/output polynomial
**************************************************/
void poly_csubq(poly *r) {
    unsigned int i;
    for (i = 0; i < S2N_KYBER_512_R3_N; i++) {
        r->coeffs[i] = csubq(r->coeffs[i]);
    }
}

/*************************************************
* Name:        poly_add
*
* Description: Add two polynomials
*
* Arguments: - poly *r:       pointer to output polynomial
*            - const poly *a: pointer to first input polynomial
*            - const poly *b: pointer to second input polynomial
**************************************************/
void poly_add(poly *r, const poly *a, const poly *b) {
    unsigned int i;
    for (i = 0; i < S2N_KYBER_512_R3_N; i++) {
        r->coeffs[i] = a->coeffs[i] + b->coeffs[i];
    }
}

/*************************************************
* Name:        poly_sub
*
* Description: Subtract two polynomials
*
* Arguments: - poly *r:       pointer to output polynomial
*            - const poly *a: pointer to first input polynomial
*            - const poly *b: pointer to second input polynomial
**************************************************/
void poly_sub(poly *r, const poly *a, const poly *b) {
    unsigned int i;
    for (i = 0; i < S2N_KYBER_512_R3_N; i++) {
        r->coeffs[i] = a->coeffs[i] - b->coeffs[i];
    }
}
