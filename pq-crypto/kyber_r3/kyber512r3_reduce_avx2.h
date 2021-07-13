#pragma once

#include <stdint.h>
#include "kyber512r3_params.h"
#include <immintrin.h>

#define reduce_avx2_asm S2N_KYBER_512_R3_NAMESPACE(reduce_avx2_asm)
void reduce_avx2_asm(int16_t *r, const int16_t *qdata);

#define csubq_avx2_asm S2N_KYBER_512_R3_NAMESPACE(csubq_avx2_asm)
void csubq_avx2_asm(int16_t *r, const int16_t *qdata);

#define tomont_avx2_asm S2N_KYBER_512_R3_NAMESPACE(tomont_avx2_asm)
void tomont_avx2_asm(int16_t *r, const int16_t *qdata);

