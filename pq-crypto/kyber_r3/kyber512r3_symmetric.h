#pragma once

#include "kyber512r3_params.h"
#include "kyber512r3_fips202.h"
#include <stdint.h>

#define keccak_state S2N_KYBER_512_R3_NAMESPACE(keccak_state)
typedef shake128ctx keccak_state;

#define xof_state S2N_KYBER_512_R3_NAMESPACE(xof_state)
typedef keccak_state xof_state;

#define kyber_shake128_absorb S2N_KYBER_512_R3_NAMESPACE(kyber_shake128_absorb)
void kyber_shake128_absorb(keccak_state *s, const uint8_t *input, uint8_t x, uint8_t y);

#define shake256_prf S2N_KYBER_512_R3_NAMESPACE(shake256_prf)
void shake256_prf(uint8_t *output, size_t outlen, const uint8_t *key, uint8_t nonce);
