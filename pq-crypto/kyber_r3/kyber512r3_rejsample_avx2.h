#pragma once

#include <stdint.h>
#include "kyber512r3_params.h"
#include "kyber512r3_fips202.h"

#if defined(S2N_KYBER512R3_AVX2_BMI2)
#define S2N_KYBER_512_R3_XOF_BLOCKBYTES S2N_KYBER_512_R3_SHAKE128_RATE
#define S2N_KYBER_512_R3_REJ_UNIFORM_AVX_NBLOCKS ((12*S2N_KYBER_512_R3_N/8*(1 << 12)/S2N_KYBER_512_R3_Q + S2N_KYBER_512_R3_XOF_BLOCKBYTES)/S2N_KYBER_512_R3_XOF_BLOCKBYTES)
#define S2N_KYBER_512_R3_REJ_UNIFORM_AVX_BUFLEN (S2N_KYBER_512_R3_REJ_UNIFORM_AVX_NBLOCKS*S2N_KYBER_512_R3_XOF_BLOCKBYTES)

#define rej_uniform_avx2 S2N_KYBER_512_R3_NAMESPACE(rej_uniform_avx2)
unsigned int rej_uniform_avx2(int16_t *r, const uint8_t *buf);
#endif
