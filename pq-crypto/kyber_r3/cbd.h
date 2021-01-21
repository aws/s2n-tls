#ifndef CBD_H
#define CBD_H

#include <stdint.h>
#include "params.h"
#include "poly.h"

#define cbd_eta1 S2N_KYBER_512_R3_NAMESPACE(_cbd_eta1)
void cbd_eta1(poly *r, const uint8_t buf[KYBER_ETA1 * KYBER_N / 4]);

#define cbd_eta2 S2N_KYBER_512_R3_NAMESPACE(_cbd_eta2)
void cbd_eta2(poly *r, const uint8_t buf[KYBER_ETA2 * KYBER_N / 4]);

#endif
