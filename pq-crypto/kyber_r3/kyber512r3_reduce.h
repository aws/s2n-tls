#pragma once

#include <stdint.h>
#include "kyber512r3_params.h"

#define S2N_KYBER_512_R3_QINV 62209 /* q^-1 mod 2^16 */

#define montgomery_reduce S2N_KYBER_512_R3_NAMESPACE(montgomery_reduce)
int16_t montgomery_reduce(int32_t a);

#define barrett_reduce S2N_KYBER_512_R3_NAMESPACE(barrett_reduce)
int16_t barrett_reduce(int16_t a);

#define csubq S2N_KYBER_512_R3_NAMESPACE(csubq)
int16_t csubq(int16_t x);
