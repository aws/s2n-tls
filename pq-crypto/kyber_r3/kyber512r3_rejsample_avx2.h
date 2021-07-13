#pragma once

#include <stdint.h>
#include "kyber512r3_params.h"

//#define XOF_BLOCKBYTES S2N_KYBER_512_R3_SHAKE128_RATE
#define XOF_BLOCKBYTES 168
#define AVX_REJ_UNIFORM_BUFLEN 504

#define rej_uniform_avx2 S2N_KYBER_512_R3_NAMESPACE(rej_uniform_avx2)
unsigned int rej_uniform_avx2(int16_t *r, const unsigned char *buf);
