#pragma once

#include <stdint.h>
#include "../kyber512r3_params.h"
#include "kyber512r3_poly_avx2.h"
#include <immintrin.h>

#define cbd_eta1_avx2 S2N_KYBER_512_R3_NAMESPACE(cbd_eta1_avx2)
void cbd_eta1_avx2(poly *r, const __m256i buf[S2N_KYBER_512_R3_ETA1 * S2N_KYBER_512_R3_N / 128 + 1]);

#define cbd_eta2_avx2 S2N_KYBER_512_R3_NAMESPACE(cbd_eta2_avx2)
void cbd_eta2_avx2(poly *r, const __m256i buf[S2N_KYBER_512_R3_ETA2 * S2N_KYBER_512_R3_N / 128]);
