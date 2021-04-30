#pragma once

#include <stdint.h>
#include "kyber512r3_params.h"

#define zetas S2N_KYBER_512_R3_NAMESPACE(zetas)
extern const int16_t zetas[128];

#define zetas_inv S2N_KYBER_512_R3_NAMESPACE(zetas_inv)
extern const int16_t zetas_inv[128];

#define ntt S2N_KYBER_512_R3_NAMESPACE(ntt)
void ntt(int16_t poly[256]);

#define invntt S2N_KYBER_512_R3_NAMESPACE(invntt)
void invntt(int16_t poly[256]);

#define basemul S2N_KYBER_512_R3_NAMESPACE(basemul)
void basemul(int16_t r[2], const int16_t a[2], const int16_t b[2], int16_t zeta);
