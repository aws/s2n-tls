#pragma once

#include "kyber512r3_params.h"
#include <immintrin.h>

//#define reduce_avx2_asm S2N_KYBER_512_R3_NAMESPACE(reduce_avx2_asm)
void reduce_avx2_asm(__m256i *r, const __m256i *qdata);

//#define tomont_avx2_asm S2N_KYBER_512_R3_NAMESPACE(tomont_avx2_asm)
void tomont_avx2_asm(__m256i *r, const __m256i *qdata);

