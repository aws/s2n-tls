#pragma once

#include <stdint.h>
#include "kyber512r3_params.h"
#include "kyber512r3_poly_avx2.h"

#if defined(S2N_KYBER512R3_AVX2_BMI2)
#include <immintrin.h>

#define poly_cbd_eta1_avx2 S2N_KYBER_512_R3_NAMESPACE(poly_cbd_eta1_avx2)
void poly_cbd_eta1_avx2(poly *r, const __m256i buf[S2N_KYBER_512_R3_ETA1*S2N_KYBER_512_R3_N/128+1]);

#define poly_cbd_eta2_avx2 S2N_KYBER_512_R3_NAMESPACE(poly_cbd_eta2_avx2)
void poly_cbd_eta2_avx2(poly *r, const __m256i buf[S2N_KYBER_512_R3_ETA2*S2N_KYBER_512_R3_N/128]);
#endif
