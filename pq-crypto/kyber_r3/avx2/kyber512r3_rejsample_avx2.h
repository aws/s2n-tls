#pragma once

#include <stdint.h>
#include "../kyber512r3_params.h"
#include "../kyber512r3_symmetric.h"

#define XOF_BLOCKBYTES 168
#define REJ_UNIFORM_AVX_NBLOCKS ((12*S2N_KYBER_512_R3_N/8*(1 << 12)/S2N_KYBER_512_R3_Q + XOF_BLOCKBYTES)/XOF_BLOCKBYTES)
#define REJ_UNIFORM_AVX_BUFLEN (REJ_UNIFORM_AVX_NBLOCKS*XOF_BLOCKBYTES)

unsigned int rej_uniform_avx2(int16_t *r, const uint8_t *buf);

