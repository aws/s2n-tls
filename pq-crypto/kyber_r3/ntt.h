#ifndef NTT_H
#define NTT_H

#include <stdint.h>
#include "params.h"

#define zetas S2N_KYBER_512_R3_NAMESPACE(_zetas)
extern const int16_t zetas[128];

#define zetas_inv S2N_KYBER_512_R3_NAMESPACE(_zetas_inv)
extern const int16_t zetas_inv[128];

#define ntt S2N_KYBER_512_R3_NAMESPACE(_ntt)
void ntt(int16_t poly[256]);

#define invntt S2N_KYBER_512_R3_NAMESPACE(_invntt)
void invntt(int16_t poly[256]);

#define basemul S2N_KYBER_512_R3_NAMESPACE(_basemul)
void basemul(int16_t r[2],
             const int16_t a[2],
             const int16_t b[2],
             int16_t zeta);

#endif
