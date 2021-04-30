#pragma once

#include <stdint.h>
#include "kyber512r3_params.h"
#include "kyber512r3_poly.h"

#define cbd_eta1 S2N_KYBER_512_R3_NAMESPACE(cbd_eta1)
void cbd_eta1(poly *r, const uint8_t buf[S2N_KYBER_512_R3_ETA1 * S2N_KYBER_512_R3_N / 4]);

#define cbd_eta2 S2N_KYBER_512_R3_NAMESPACE(cbd_eta2)
void cbd_eta2(poly *r, const uint8_t buf[S2N_KYBER_512_R3_ETA2 * S2N_KYBER_512_R3_N / 4]);
