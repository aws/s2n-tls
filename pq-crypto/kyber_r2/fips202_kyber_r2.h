// SPDX-License-Identifier: MIT

#ifndef FIPS202_KYBER_R2_H
#define FIPS202_KYBER_R2_H

#include <stdint.h>
#include <stddef.h>

/** Data structure for the state of the SHAKE128 non-incremental hashing API. */
typedef struct {
	/** Internal state. */
	void *ctx;
} shake128ctx;

/** Data structure for the state of the SHAKE256 non-incremental hashing API. */
typedef struct {
	/** Internal state. */
	void *ctx;
} shake256ctx;

typedef shake128ctx keccak_state;


#define SHAKE128_RATE 168
#define SHAKE256_RATE 136
#define SHA3_256_RATE 136
#define SHA3_512_RATE 72

void shake128_absorb(shake128ctx *state, const uint8_t *input, size_t inlen);
void shake128_squeezeblocks(uint8_t *output, size_t nblocks, shake128ctx *state);
void shake256_kyber(uint8_t *output, size_t outlen, const uint8_t *input, size_t inlen);
void sha3_256(uint8_t *output, const uint8_t *input, size_t inlen);
void sha3_512(uint8_t *output, const uint8_t *input, size_t inlen);
void shake128_ctx_release(shake128ctx *state);

#endif // FIPS202_KYBER_R2_H
