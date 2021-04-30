#include <stdint.h>
#include "kyber512r3_params.h"
#include "kyber512r3_poly.h"
#include "kyber512r3_polyvec.h"

/*************************************************
* Name:        polyvec_compress
*
* Description: Compress and serialize vector of polynomials
*
* Arguments:   - uint8_t *r: pointer to output byte array
*                            (needs space for S2N_KYBER_512_R3_POLYVECCOMPRESSEDBYTES)
*              - polyvec *a: pointer to input vector of polynomials
**************************************************/
void polyvec_compress(uint8_t r[S2N_KYBER_512_R3_POLYVECCOMPRESSEDBYTES], polyvec *a) {
    polyvec_csubq(a);

    uint16_t t[4];
    for (unsigned int i = 0; i < S2N_KYBER_512_R3_K; i++) {
        for (unsigned int  j = 0; j < S2N_KYBER_512_R3_N / 4; j++) {
            for (unsigned int  k = 0; k < 4; k++)
                t[k] = ((((uint32_t)a->vec[i].coeffs[4 * j + k] << 10) + S2N_KYBER_512_R3_Q / 2)
                        / S2N_KYBER_512_R3_Q) & 0x3ff;

            r[0] = (t[0] >> 0);
            r[1] = (t[0] >> 8) | (t[1] << 2);
            r[2] = (t[1] >> 6) | (t[2] << 4);
            r[3] = (t[2] >> 4) | (t[3] << 6);
            r[4] = (t[3] >> 2);
            r += 5;
        }
    }
}

/*************************************************
* Name:        polyvec_decompress
*
* Description: De-serialize and decompress vector of polynomials;
*              approximate inverse of polyvec_compress
*
* Arguments:   - polyvec *r:       pointer to output vector of polynomials
*              - const uint8_t *a: pointer to input byte array
*                                  (of length S2N_KYBER_512_R3_POLYVECCOMPRESSEDBYTES)
**************************************************/
void polyvec_decompress(polyvec *r, const uint8_t a[S2N_KYBER_512_R3_POLYVECCOMPRESSEDBYTES]) {
    uint16_t t[4];
    for (unsigned int  i = 0; i < S2N_KYBER_512_R3_K; i++) {
        for (unsigned int  j = 0; j < S2N_KYBER_512_R3_N / 4; j++) {
            t[0] = (a[0] >> 0) | ((uint16_t)a[1] << 8);
            t[1] = (a[1] >> 2) | ((uint16_t)a[2] << 6);
            t[2] = (a[2] >> 4) | ((uint16_t)a[3] << 4);
            t[3] = (a[3] >> 6) | ((uint16_t)a[4] << 2);
            a += 5;

            for (unsigned int  k = 0; k < 4; k++) {
                r->vec[i].coeffs[4 * j + k] = ((uint32_t)(t[k] & 0x3FF) * S2N_KYBER_512_R3_Q + 512) >> 10;
            }
        }
    }
}

/*************************************************
* Name:        polyvec_tobytes
*
* Description: Serialize vector of polynomials
*
* Arguments:   - uint8_t *r: pointer to output byte array
*                            (needs space for S2N_KYBER_512_R3_POLYVECBYTES)
*              - polyvec *a: pointer to input vector of polynomials
**************************************************/
void polyvec_tobytes(uint8_t r[S2N_KYBER_512_R3_POLYVECBYTES], polyvec *a) {
    for (unsigned int  i = 0; i < S2N_KYBER_512_R3_K; i++) {
        poly_tobytes(r + i * S2N_KYBER_512_R3_POLYBYTES, &a->vec[i]);
    }
}

/*************************************************
* Name:        polyvec_frombytes
*
* Description: De-serialize vector of polynomials;
*              inverse of polyvec_tobytes
*
* Arguments:   - uint8_t *r:       pointer to output byte array
*              - const polyvec *a: pointer to input vector of polynomials
*                                  (of length S2N_KYBER_512_R3_POLYVECBYTES)
**************************************************/
void polyvec_frombytes(polyvec *r, const uint8_t a[S2N_KYBER_512_R3_POLYVECBYTES]) {
    for (unsigned int  i = 0; i < S2N_KYBER_512_R3_K; i++) {
        poly_frombytes(&r->vec[i], a + i * S2N_KYBER_512_R3_POLYBYTES);
    }
}

/*************************************************
* Name:        polyvec_ntt
*
* Description: Apply forward NTT to all elements of a vector of polynomials
*
* Arguments:   - polyvec *r: pointer to in/output vector of polynomials
**************************************************/
void polyvec_ntt(polyvec *r) {
    for (unsigned int  i = 0; i < S2N_KYBER_512_R3_K; i++) {
        poly_ntt(&r->vec[i]);
    }
}

/*************************************************
* Name:        polyvec_invntt_tomont
*
* Description: Apply inverse NTT to all elements of a vector of polynomials
*              and multiply by Montgomery factor 2^16
*
* Arguments:   - polyvec *r: pointer to in/output vector of polynomials
**************************************************/
void polyvec_invntt_tomont(polyvec *r) {
    for (unsigned int  i = 0; i < S2N_KYBER_512_R3_K; i++) {
        poly_invntt_tomont(&r->vec[i]);
    }
}

/*************************************************
* Name:        polyvec_pointwise_acc_montgomery
*
* Description: Pointwise multiply elements of a and b, accumulate into r,
*              and multiply by 2^-16.
*
* Arguments: - poly *r:          pointer to output polynomial
*            - const polyvec *a: pointer to first input vector of polynomials
*            - const polyvec *b: pointer to second input vector of polynomials
**************************************************/
void polyvec_pointwise_acc_montgomery(poly *r, const polyvec *a, const polyvec *b) {
    poly t;

    poly_basemul_montgomery(r, &a->vec[0], &b->vec[0]);
    for (unsigned int  i = 1; i < S2N_KYBER_512_R3_K; i++) {
        poly_basemul_montgomery(&t, &a->vec[i], &b->vec[i]);
        poly_add(r, r, &t);
    }

    poly_reduce(r);
}

/*************************************************
* Name:        polyvec_reduce
*
* Description: Applies Barrett reduction to each coefficient
*              of each element of a vector of polynomials
*              for details of the Barrett reduction see comments in reduce.c
*
* Arguments:   - poly *r: pointer to input/output polynomial
**************************************************/
void polyvec_reduce(polyvec *r) {
    for (unsigned int  i = 0; i < S2N_KYBER_512_R3_K; i++) {
        poly_reduce(&r->vec[i]);
    }
}

/*************************************************
* Name:        polyvec_csubq
*
* Description: Applies conditional subtraction of q to each coefficient
*              of each element of a vector of polynomials
*              for details of conditional subtraction of q see comments in
*              reduce.c
*
* Arguments:   - poly *r: pointer to input/output polynomial
**************************************************/
void polyvec_csubq(polyvec *r) {
    for (unsigned int  i = 0; i < S2N_KYBER_512_R3_K; i++) {
        poly_csubq(&r->vec[i]);
    }
}

/*************************************************
* Name:        polyvec_add
*
* Description: Add vectors of polynomials
*
* Arguments: - polyvec *r:       pointer to output vector of polynomials
*            - const polyvec *a: pointer to first input vector of polynomials
*            - const polyvec *b: pointer to second input vector of polynomials
**************************************************/
void polyvec_add(polyvec *r, const polyvec *a, const polyvec *b) {
    for (unsigned int  i = 0; i < S2N_KYBER_512_R3_K; i++) {
        poly_add(&r->vec[i], &a->vec[i], &b->vec[i]);
    }
}
