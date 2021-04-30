#pragma once

#include <stddef.h>
#include <stdint.h>
#include "kyber512r3_params.h"

#define S2N_KYBER_512_R3_SHAKE128_RATE 168
#define S2N_KYBER_512_R3_SHAKE256_RATE 136
#define S2N_KYBER_512_R3_SHA3_256_RATE 136
#define S2N_KYBER_512_R3_SHA3_384_RATE 104
#define S2N_KYBER_512_R3_SHA3_512_RATE 72

#define S2N_KYBER_512_R3_PQC_SHAKECTX_SIZE 25

/* Context for non-incremental API */
#define shake128ctx S2N_KYBER_512_R3_NAMESPACE(shake128ctx)
typedef struct {
    uint64_t ctx[S2N_KYBER_512_R3_PQC_SHAKECTX_SIZE];
} shake128ctx;

/* Context for non-incremental API */
#define shake256ctx S2N_KYBER_512_R3_NAMESPACE(shake256ctx)
typedef struct {
    uint64_t ctx[S2N_KYBER_512_R3_PQC_SHAKECTX_SIZE];
} shake256ctx;

/* Initialize the state and absorb the provided input.
 *
 * This function does not support being called multiple times
 * with the same state.
 */
#define shake128_absorb S2N_KYBER_512_R3_NAMESPACE(shake128_absorb)
void shake128_absorb(shake128ctx *state, const uint8_t *input, size_t inlen);
/* Squeeze output out of the sponge.
 *
 * Supports being called multiple times
 */
#define shake128_squeezeblocks S2N_KYBER_512_R3_NAMESPACE(shake128_squeezeblocks)
void shake128_squeezeblocks(uint8_t *output, size_t nblocks, shake128ctx *state);

/* Copy the state. */
#define shake128_ctx_clone S2N_KYBER_512_R3_NAMESPACE(shake128_ctx_clone)
void shake128_ctx_clone(shake128ctx *dest, const shake128ctx *src);

/* Initialize the state and absorb the provided input.
 *
 * This function does not support being called multiple times
 * with the same state.
 */
#define shake256_absorb S2N_KYBER_512_R3_NAMESPACE(shake256_absorb)
void shake256_absorb(shake256ctx *state, const uint8_t *input, size_t inlen);
/* Squeeze output out of the sponge.
 *
 * Supports being called multiple times
 */
#define shake256_squeezeblocks S2N_KYBER_512_R3_NAMESPACE(shake256_squeezeblocks)
void shake256_squeezeblocks(uint8_t *output, size_t nblocks, shake256ctx *state);

/* One-stop SHAKE256 call */
#define shake256 S2N_KYBER_512_R3_NAMESPACE(shake256)
void shake256(uint8_t *output, size_t outlen, const uint8_t *input, size_t inlen);

#define sha3_256 S2N_KYBER_512_R3_NAMESPACE(sha3_256)
void sha3_256(uint8_t *output, const uint8_t *input, size_t inlen);

/* One-stop SHA3-512 shop */
#define sha3_512 S2N_KYBER_512_R3_NAMESPACE(sha3_512)
void sha3_512(uint8_t *output, const uint8_t *input, size_t inlen);
