#ifndef FIPS202_H
#define FIPS202_H

#include <stdio.h>
#include <stddef.h>
#include <stdint.h>


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


#define SHA3_256_RATE OQS_SHA3_SHA3_256_RATE
#define SHA3_512_RATE OQS_SHA3_SHA3_512_RATE
#define SHAKE128_RATE OQS_SHA3_SHAKE128_RATE
#define SHAKE256_RATE OQS_SHA3_SHAKE256_RATE

#define OQS_SHA3_SHA3_256_RATE 136
#define OQS_SHA3_SHA3_512_RATE 72
#define OQS_SHA3_SHAKE128_RATE 168
#define OQS_SHA3_SHAKE256_RATE 136


/** Data structure for the state of the SHAKE128 non-incremental hashing API. */
//typedef struct {
//	/** Internal state. */
//	void *ctx;
//} OQS_SHA3_shake128_ctx;


//#define shake128ctx OQS_SHA3_shake128_ctx



void shake128_absorb(shake128ctx *state, const uint8_t *input, size_t inlen);
void shake128_squeezeblocks(uint8_t *output, size_t nblocks, shake128ctx *state);
void shake256_k(uint8_t *output, size_t outlen, const uint8_t *input, size_t inlen);
void sha3_256(uint8_t *output, const uint8_t *input, size_t inlen);
void sha3_512(uint8_t *output, const uint8_t *input, size_t inlen);
void shake128_ctx_release(shake128ctx *state);

#endif // FIPS202_H
