#pragma once

#include <stdint.h>
#include "kyber512r3_params.h"
#include "kyber512r3_poly_avx2.h"

#define cbd_eta1_avx2 S2N_KYBER_512_R3_NAMESPACE(cbd_eta1_avx2)
void cbd_eta1_avx2(poly *r, const uint8_t buf[S2N_KYBER_512_R3_ETA1*S2N_KYBER_512_R3_N/4]);

#define cbd_eta2_avx2 S2N_KYBER_512_R3_NAMESPACE(cbd_eta2_avx2)
void cbd_eta2_avx2(poly *r, const uint8_t buf[S2N_KYBER_512_R3_ETA2*S2N_KYBER_512_R3_N/4]);
