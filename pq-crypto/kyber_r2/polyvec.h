#ifndef POLYVEC_H
#define POLYVEC_H

#include "params.h"
#include "poly.h"

#include <stdint.h>

typedef struct {
    poly vec[KYBER_K];
} polyvec;

void PQCLEAN_KYBER512_CLEAN_polyvec_compress(uint8_t *r, polyvec *a);
void PQCLEAN_KYBER512_CLEAN_polyvec_decompress(polyvec *r, const uint8_t *a);

void PQCLEAN_KYBER512_CLEAN_polyvec_tobytes(uint8_t *r, polyvec *a);
void PQCLEAN_KYBER512_CLEAN_polyvec_frombytes(polyvec *r, const uint8_t *a);

void PQCLEAN_KYBER512_CLEAN_polyvec_ntt(polyvec *r);
void PQCLEAN_KYBER512_CLEAN_polyvec_invntt(polyvec *r);

void PQCLEAN_KYBER512_CLEAN_polyvec_pointwise_acc(poly *r, const polyvec *a, const polyvec *b);

void PQCLEAN_KYBER512_CLEAN_polyvec_reduce(polyvec *r);
void PQCLEAN_KYBER512_CLEAN_polyvec_csubq(polyvec *r);

void PQCLEAN_KYBER512_CLEAN_polyvec_add(polyvec *r, const polyvec *a, const polyvec *b);

#endif
