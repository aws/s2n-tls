/**
 * \file sha3.h
 * \brief SHA3, SHAKE, and cSHAKE functions; not part of the OQS public API
 *
 * Contains the API and documentation for SHA3 digest and SHAKE implementations.
 *
 * <b>Note this is not part of the OQS public API: implementations within liboqs can use these
 * functions, but external consumers of liboqs should not use these functions.</b>
 *
 * \author John Underhill, Douglas Stebila
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef OQS_SHA3_H
#define OQS_SHA3_H

#include <stddef.h>
#include <stdint.h>

#if defined(__cplusplus)
extern "C" {
#endif

/* SHA3 */

/** The SHA-256 byte absorption rate */
#define OQS_SHA3_SHA3_256_RATE 136

/**
 * \brief Process a message with SHA3-256 and return the hash code in the output byte array.
 *
 * \warning The output array must be at least 32 bytes in length.
 *
 * \param output The output byte array
 * \param input The message input byte array
 * \param inplen The number of message bytes to process
 */
void OQS_SHA3_sha3_256(uint8_t *output, const uint8_t *input, size_t inplen);

/** Data structure for the state of the SHA3-256 incremental hashing API. */
typedef struct {
	/** Internal state. */
	void *ctx;
} OQS_SHA3_sha3_256_inc_ctx;

/**
 * \brief Initialize the state for the SHA3-256 incremental hashing API.
 *
 * \warning State must be allovated by the caller. Caller is responsible
 * for releasing state by calling either OQS_SHA3_sha3_256_inc_finalize or
 * OQS_SHA3_sha3_256_inc_ctx_release.
 *
 * \param state The function state to be initialized; must be allocated.
 */
void OQS_SHA3_sha3_256_inc_init(OQS_SHA3_sha3_256_inc_ctx *state);

/**
 * \brief The SHA3-256 absorb function.
 * Absorb an input message array directly into the state.
 *
 * \warning State must be initialized by the caller.
 *
 * \param state The function state; must be initialized
 * \param input The input message byte array
 * \param inlen The number of message bytes to process
 */
void OQS_SHA3_sha3_256_inc_absorb(OQS_SHA3_sha3_256_inc_ctx *state, const uint8_t *input, size_t inlen);

/**
 * \brief The SHA3-256 squeeze/finalize function.
 * Permutes and extracts the state to an output byte array.
 * Releases state.
 *
 * \warning Output array must be allocated.
 * State cannot be used after this without re-calling OQS_SHA3_sha3_256_inc_init.

 * \param output The output byte array
 * \param state The function state; must be initialized
 */
void OQS_SHA3_sha3_256_inc_finalize(uint8_t *output, OQS_SHA3_sha3_256_inc_ctx *state);

/**
 * \brief Release the state for the SHA3-256 incremental API.
 *
 * \warning State cannot be used after this without re-calling OQS_SHA3_sha3_256_inc_init.
 *
 * \param state The function state; must be initialized
 */
void OQS_SHA3_sha3_256_inc_ctx_release(OQS_SHA3_sha3_256_inc_ctx *state);

/**
 * \brief Clone the state for the SHA3-256 incremental API.
 *
 * \warning dest must be allocated by the caller. Caller is responsible
 * for releasing dest by calling either OQS_SHA3_sha3_256_inc_finalize or
 * OQS_SHA3_sha3_256_inc_ctx_release.
 *
 * \param dest The function state to copy into; must be initialized
 * \param src The function state to copy; must be initialized
 */
void OQS_SHA3_sha3_256_inc_ctx_clone(OQS_SHA3_sha3_256_inc_ctx *dest, const OQS_SHA3_sha3_256_inc_ctx *src);

/** The SHA-384 byte absorption rate */
#define OQS_SHA3_SHA3_384_RATE 104

/**
 * \brief Process a message with SHA3-384 and return the hash code in the output byte array.
 *
 * \warning The output array must be at least 48 bytes in length.
 *
 * \param output The output byte array
 * \param input The message input byte array
 * \param inplen The number of message bytes to process
 */
void OQS_SHA3_sha3_384(uint8_t *output, const uint8_t *input, size_t inplen);

/** Data structure for the state of the SHA3-384 incremental hashing API. */
typedef struct {
	/** Internal state. */
	void *ctx;
} OQS_SHA3_sha3_384_inc_ctx;

/**
 * \brief Initialize the state for the SHA3-384 incremental hashing API.
 *
 * \warning State must be allovated by the caller. Caller is responsible
 * for releasing state by calling either OQS_SHA3_sha3_384_inc_finalize or
 * OQS_SHA3_sha3_384_inc_ctx_release.
 *
 * \param state The function state to be initialized; must be allocated.
 */
void OQS_SHA3_sha3_384_inc_init(OQS_SHA3_sha3_384_inc_ctx *state);

/**
 * \brief The SHA3-384 absorb function.
 * Absorb an input message array directly into the state.
 *
 * \warning State must be initialized by the caller.
 *
 * \param state The function state; must be initialized
 * \param input The input message byte array
 * \param inlen The number of message bytes to process
 */
void OQS_SHA3_sha3_384_inc_absorb(OQS_SHA3_sha3_384_inc_ctx *state, const uint8_t *input, size_t inlen);

/**
 * \brief The SHA3-384 squeeze/finalize function.
 * Permutes and extracts the state to an output byte array.
 * Releases state.
 *
 * \warning Output array must be allocated.
 * State cannot be used after this without re-calling OQS_SHA3_sha3_384_inc_init.

 * \param output The output byte array
 * \param state The function state; must be initialized
 */
void OQS_SHA3_sha3_384_inc_finalize(uint8_t *output, OQS_SHA3_sha3_384_inc_ctx *state);

/**
 * \brief Release the state for the SHA3-384 incremental API.
 *
 * \warning State cannot be used after this without re-calling OQS_SHA3_sha3_384_inc_init.
 *
 * \param state The function state; must be initialized
 */
void OQS_SHA3_sha3_384_inc_ctx_release(OQS_SHA3_sha3_384_inc_ctx *state);

/**
 * \brief Clone the state for the SHA3-384 incremental API.
 *
 * \warning dest must be allovated by the caller. Caller is responsible
 * for releasing dest by calling either OQS_SHA3_sha3_384_inc_finalize or
 * OQS_SHA3_sha3_384_inc_ctx_release.
 *
 * \param dest The function state to copy into; must be initialized
 * \param src The function state to copy; must be initialized
 */
void OQS_SHA3_sha3_384_inc_ctx_clone(OQS_SHA3_sha3_384_inc_ctx *dest, const OQS_SHA3_sha3_384_inc_ctx *src);

/** The SHA-512 byte absorption rate */
#define OQS_SHA3_SHA3_512_RATE 72

/**
 * \brief Process a message with SHA3-512 and return the hash code in the output byte array.
 *
 * \warning The output array must be at least 64 bytes in length.
 *
 * \param output The output byte array
 * \param input The message input byte array
 * \param inplen The number of message bytes to process
 */
void OQS_SHA3_sha3_512(uint8_t *output, const uint8_t *input, size_t inplen);

/** Data structure for the state of the SHA3-512 incremental hashing API. */
typedef struct {
	/** Internal state. */
	void *ctx;
} OQS_SHA3_sha3_512_inc_ctx;

/**
 * \brief Initialize the state for the SHA3-512 incremental hashing API.
 *
 * \warning State must be allovated by the caller. Caller is responsible
 * for releasing state by calling either OQS_SHA3_sha3_512_inc_finalize or
 * OQS_SHA3_sha3_512_inc_ctx_release.
 *
 * \param state The function state to be initialized; must be allocated.
 */
void OQS_SHA3_sha3_512_inc_init(OQS_SHA3_sha3_512_inc_ctx *state);

/**
 * \brief The SHA3-512 absorb function.
 * Absorb an input message array directly into the state.
 *
 * \warning State must be initialized by the caller.
 *
 * \param state The function state; must be initialized
 * \param input The input message byte array
 * \param inlen The number of message bytes to process
 */
void OQS_SHA3_sha3_512_inc_absorb(OQS_SHA3_sha3_512_inc_ctx *state, const uint8_t *input, size_t inlen);

/**
 * \brief The SHA3-512 squeeze/finalize function.
 * Permutes and extracts the state to an output byte array.
 * Releases state.
 *
 * \warning Output array must be allocated.
 * State cannot be used after this without re-calling OQS_SHA3_sha3_512_inc_init.

 * \param output The output byte array
 * \param state The function state; must be initialized
 */
void OQS_SHA3_sha3_512_inc_finalize(uint8_t *output, OQS_SHA3_sha3_512_inc_ctx *state);

/**
 * \brief Release the state for the SHA3-512 incremental API.
 *
 * \warning State cannot be used after this without re-calling OQS_SHA3_sha3_512_inc_init.
 *
 * \param state The function state; must be initialized
 */
void OQS_SHA3_sha3_512_inc_ctx_release(OQS_SHA3_sha3_512_inc_ctx *state);

/**
 * \brief Clone the state for the SHA3-512 incremental API.
 *
 * \warning dest must be allovated by the caller. Caller is responsible
 * for releasing dest by calling either OQS_SHA3_sha3_512_inc_finalize or
 * OQS_SHA3_sha3_512_inc_ctx_release.
 *
 * \param dest The function state to copy into; must be initialized
 * \param src The function state to copy; must be initialized
 */
void OQS_SHA3_sha3_512_inc_ctx_clone(OQS_SHA3_sha3_512_inc_ctx *dest, const OQS_SHA3_sha3_512_inc_ctx *src);

/* SHAKE */

/** The SHAKE-128 byte absorption rate */
#define OQS_SHA3_SHAKE128_RATE 168

/**
 * \brief Seed a SHAKE-128 instance, and generate an array of pseudo-random bytes.
 *
 * \warning The output array length must not be zero.
 *
 * \param output The output byte array
 * \param outlen The number of output bytes to generate
 * \param input The input seed byte array
 * \param inplen The number of seed bytes to process
 */
void OQS_SHA3_shake128(uint8_t *output, size_t outlen, const uint8_t *input, size_t inplen);

/** Data structure for the state of the SHAKE128 non-incremental hashing API. */
typedef struct {
	/** Internal state. */
	void *ctx;
} OQS_SHA3_shake128_ctx;

/**
 * \brief The SHAKE-128 absorb function.
 * Absorb and finalize an input seed byte array.
 * Should be used in conjunction with the shake128_squeezeblocks function.
 *
 * \warning Finalizes the seed state, should not be used in consecutive calls.
 * State must be allocated by the caller. State msut be freed by calling
 * OQS_SHA3_shake128_ctx_release.
 *
 * \param state The function state; must be allocated
 * \param input The input seed byte array
 * \param inplen The number of seed bytes to process
 */
void OQS_SHA3_shake128_absorb(OQS_SHA3_shake128_ctx *state, const uint8_t *input, size_t inplen);

/**
 * \brief The SHAKE-128 squeeze function.
 * Permutes and extracts the state to an output byte array.
 * Should be used in conjunction with the shake128_absorb function.
 *
 * \warning Output array must be initialized to a multiple of the byte rate.
 *
 * \param output The output byte array
 * \param nblocks The number of blocks to extract
 * \param state The function state; must be allocated
 */
void OQS_SHA3_shake128_squeezeblocks(uint8_t *output, size_t nblocks, OQS_SHA3_shake128_ctx *state);

/**
 * \brief Frees the state for SHAKE-128.
 *
 * \param state The state to free
 */
void OQS_SHA3_shake128_ctx_release(OQS_SHA3_shake128_ctx *state);

/**
 * \brief Copies the state for SHAKE-128.
 *
 * \warning dest must be allocated. dest must be freed by calling
 * OQS_SHA3_shake128_ctx_release.
 *
 * \param dest The state to copy into
 * \param src The state to copy from
 */
void OQS_SHA3_shake128_ctx_clone(OQS_SHA3_shake128_ctx *dest, const OQS_SHA3_shake128_ctx *src);

/** Data structure for the state of the SHAKE-128 incremental hashing API. */
typedef struct {
	/** Internal state. */
	void *ctx;
} OQS_SHA3_shake128_inc_ctx;

/**
 * \brief Initialize the state for the SHAKE-128 incremental hashing API.
 *
 * \param state The function state to be initialized; must be allocated
 */
void OQS_SHA3_shake128_inc_init(OQS_SHA3_shake128_inc_ctx *state);

/**
 * \brief The SHAKE-128 absorb function.
 * Absorb an input message array directly into the state.
 *
 * \warning State must be initialized by the caller.
 *
 * \param state The function state; must be initialized
 * \param input input buffer
 * \param inlen length of input buffer
 */
void OQS_SHA3_shake128_inc_absorb(OQS_SHA3_shake128_inc_ctx *state, const uint8_t *input, size_t inlen);

/**
 * \brief The SHAKE-128 finalize function.
 *
 * \param state The function state; must be initialized
 */
void OQS_SHA3_shake128_inc_finalize(OQS_SHA3_shake128_inc_ctx *state);

/**
 * \brief The SHAKE-128 squeeze function.
 * Extracts to an output byte array.
 *
 * \param output output buffer
 * \param outlen bytes of outbut buffer
 * \param state The function state; must be initialized
 */
void OQS_SHA3_shake128_inc_squeeze(uint8_t *output, size_t outlen, OQS_SHA3_shake128_inc_ctx *state);

/**
 * \brief Frees the state for the SHAKE-128 incremental hashing API.
 *
 * \param state The state to free
 */
void OQS_SHA3_shake128_inc_ctx_release(OQS_SHA3_shake128_inc_ctx *state);

/**
 * \brief Copies the state for the SHAKE-128 incremental hashing API.
 *
 * \warning dest must be allocated. dest must be freed by calling
 * OQS_SHA3_shake128_inc_ctx_release.
 *
 * \param dest The state to copy into
 * \param src The state to copy from
 */
void OQS_SHA3_shake128_inc_ctx_clone(OQS_SHA3_shake128_inc_ctx *dest, const OQS_SHA3_shake128_inc_ctx *src);

/** The SHAKE-256 byte absorption rate */
#define OQS_SHA3_SHAKE256_RATE 136

/**
 * \brief Seed a SHAKE-256 instance, and generate an array of pseudo-random bytes.
 *
 * \warning The output array length must not be zero.
 *
 * \param output The output byte array
 * \param outlen The number of output bytes to generate
 * \param input The input seed byte array
 * \param inplen The number of seed bytes to process
 */
void OQS_SHA3_shake256(uint8_t *output, size_t outlen, const uint8_t *input, size_t inplen);

/** Data structure for the state of the SHAKE256 non-incremental hashing API. */
typedef struct {
	/** Internal state. */
	void *ctx;
} OQS_SHA3_shake256_ctx;

/**
 * \brief The SHAKE-256 absorb function.
 * Absorb and finalize an input seed byte array.
 * Should be used in conjunction with the shake256_squeezeblocks function.
 *
 * \warning Finalizes the seed state, should not be used in consecutive calls.
 * State must be allocated by the caller. State msut be freed by calling
 * OQS_SHA3_shake256_ctx_release.
 *
 * \param state The function state; must be allocated
 * \param input The input seed byte array
 * \param inplen The number of seed bytes to process
 */
void OQS_SHA3_shake256_absorb(OQS_SHA3_shake256_ctx *state, const uint8_t *input, size_t inplen);

/**
 * \brief The SHAKE-256 squeeze function.
 * Permutes and extracts the state to an output byte array.
 * Should be used in conjunction with the shake256_absorb function.
 *
 * \warning Output array must be initialized to a multiple of the byte rate.
 *
 * \param output The output byte array
 * \param nblocks The number of blocks to extract
 * \param state The function state; must be allocated
 */
void OQS_SHA3_shake256_squeezeblocks(uint8_t *output, size_t nblocks, OQS_SHA3_shake256_ctx *state);

/**
 * \brief Frees the state for SHAKE-256.
 *
 * \param state The state to free
 */
void OQS_SHA3_shake256_ctx_release(OQS_SHA3_shake256_ctx *state);

/**
 * \brief Copies the state for SHAKE-256.
 *
 * \warning dest must be allocated. dest must be freed by calling
 * OQS_SHA3_shake256_ctx_release.
 *
 * \param dest The state to copy into
 * \param src The state to copy from
 */
void OQS_SHA3_shake256_ctx_clone(OQS_SHA3_shake256_ctx *dest, const OQS_SHA3_shake256_ctx *src);

/** Data structure for the state of the SHAKE-256 incremental hashing API. */
typedef struct {
	/** Internal state. */
	void *ctx;
} OQS_SHA3_shake256_inc_ctx;

/**
 * \brief Initialize the state for the SHAKE-256 incremental hashing API.
 *
 * \param state The function state to be initialized; must be allocated
 */
void OQS_SHA3_shake256_inc_init(OQS_SHA3_shake256_inc_ctx *state);

/**
 * \brief The SHAKE-256 absorb function.
 * Absorb an input message array directly into the state.
 *
 * \warning State must be initialized by the caller.
 *
 * \param state The function state; must be initialized
 * \param input input buffer
 * \param inlen length of input buffer
 */
void OQS_SHA3_shake256_inc_absorb(OQS_SHA3_shake256_inc_ctx *state, const uint8_t *input, size_t inlen);

/**
 * \brief The SHAKE-256 finalize function.
 *
 * \param state The function state; must be initialized
 */
void OQS_SHA3_shake256_inc_finalize(OQS_SHA3_shake256_inc_ctx *state);

/**
 * \brief The SHAKE-256 squeeze function.
 * Extracts to an output byte array.
 *
 * \param output output buffer
 * \param outlen bytes of outbut buffer
 * \param state The function state; must be initialized
 */
void OQS_SHA3_shake256_inc_squeeze(uint8_t *output, size_t outlen, OQS_SHA3_shake256_inc_ctx *state);

/**
 * \brief Frees the state for the SHAKE-256 incremental hashing API.
 *
 * \param state The state to free
 */
void OQS_SHA3_shake256_inc_ctx_release(OQS_SHA3_shake256_inc_ctx *state);

/**
 * \brief Copies the state for the SHAKE-256 incremental hashing API.
 *
 * \warning dest must be allocated. dest must be freed by calling
 * OQS_SHA3_shake256_inc_ctx_release.
 *
 * \param dest The state to copy into
 * \param src The state to copy from
 */
void OQS_SHA3_shake256_inc_ctx_clone(OQS_SHA3_shake256_inc_ctx *dest, const OQS_SHA3_shake256_inc_ctx *src);

/* cSHAKE */

/**
 * \brief Seed a cSHAKE-128 instance and generate pseudo-random output.
 * Permutes and extracts the state to an output byte array.
 *
 * \warning This function has a counter period of 2^16.
 *
 * \param output The output byte array
 * \param outlen The number of output bytes to generate
 * \param name The function name input as a byte array
 * \param namelen The length of the function name byte array
 * \param cstm The customization string as a byte array
 * \param cstmlen The length of the customization string byte array
 * \param input The input seed byte array
 * \param inlen The number of seed bytes to process
 */
void OQS_SHA3_cshake128(uint8_t *output, size_t outlen, const uint8_t *name, size_t namelen, const uint8_t *cstm, size_t cstmlen, const uint8_t *input, size_t inlen);

/**
 * \brief Initialize the state for the cSHAKE-128 incremental hashing API.
 *
 * \param state The function state to be initialized; must be allocated
 * \param name The function name input as a byte array
 * \param namelen The length of the function name byte array
 * \param cstm The customization string as a byte array
 * \param cstmlen The length of the customization string byte array
 */
void OQS_SHA3_cshake128_inc_init(OQS_SHA3_shake128_inc_ctx *state, const uint8_t *name, size_t namelen, const uint8_t *cstm, size_t cstmlen);

/**
 * \brief The cSHAKE-128 absorb function.
 * Absorb an input message array directly into the state.
 *
 * \warning State must be initialized by the caller.
 *
 * \param state state
 * \param input input buffer
 * \param inlen length of input buffer
 */
void OQS_SHA3_cshake128_inc_absorb(OQS_SHA3_shake128_inc_ctx *state, const uint8_t *input, size_t inlen);

/**
 * \brief The cSHAKE-128 finalize function.
 *
 * \param state The function state; must be initialized
 */
void OQS_SHA3_cshake128_inc_finalize(OQS_SHA3_shake128_inc_ctx *state);

/**
 * \brief The cSHAKE-128 squeeze function.
 * Extracts to an output byte array.
 *
 * \param output output buffer
 * \param outlen bytes of outbut buffer
 * \param state The function state; must be initialized
 */
void OQS_SHA3_cshake128_inc_squeeze(uint8_t *output, size_t outlen, OQS_SHA3_shake128_inc_ctx *state);

/**
 * \brief Free the cSHAKE-128 incremental context.
 *
 * \param state The function state; must be initialized
 */
void OQS_SHA3_cshake128_inc_ctx_release(OQS_SHA3_shake128_inc_ctx *state);

/**
 * \brief Copies the state for the cSHAKE-128 incremental hashing API.
 *
 * \warning dest must be allocated. dest must be freed by calling
 * OQS_SHA3_cshake128_inc_ctx_release.
 *
 * \param dest The state to copy into
 * \param src The state to copy from
 */
void OQS_SHA3_cshake128_inc_ctx_clone(OQS_SHA3_shake128_inc_ctx *dest, const OQS_SHA3_shake128_inc_ctx *src);

/**
 * \brief Seed a cSHAKE-256 instance and generate pseudo-random output.
 * Permutes and extracts the state to an output byte array.
 *
 * \warning This function has a counter period of 2^16.
 *
 * \param output The output byte array
 * \param outlen The number of output bytes to generate
 * \param name The function name input as a byte array
 * \param namelen The length of the function name byte array
 * \param cstm The customization string as a byte array
 * \param cstmlen The length of the customization string byte array
 * \param input The input seed byte array
 * \param inlen The number of seed bytes to process
 */
void OQS_SHA3_cshake256(uint8_t *output, size_t outlen, const uint8_t *name, size_t namelen, const uint8_t *cstm, size_t cstmlen, const uint8_t *input, size_t inlen);

/**
 * \brief Initialize the state for the cSHAKE-256 incremental hashing API.
 *
 * \param state The function state to be initialized; must be allocated
 * \param name The function name input as a byte array
 * \param namelen The length of the function name byte array
 * \param cstm The customization string as a byte array
 * \param cstmlen The length of the customization string byte array
 */
void OQS_SHA3_cshake256_inc_init(OQS_SHA3_shake256_inc_ctx *state, const uint8_t *name, size_t namelen, const uint8_t *cstm, size_t cstmlen);

/**
 * \brief The cSHAKE-256 absorb function.
 * Absorb an input message array directly into the state.
 *
 * \warning State must be initialized by the caller.
 *
 * \param state state
 * \param input input buffer
 * \param inlen length of input buffer
 */
void OQS_SHA3_cshake256_inc_absorb(OQS_SHA3_shake256_inc_ctx *state, const uint8_t *input, size_t inlen);

/**
 * \brief The cSHAKE-256 finalize function.
 *
 * \param state The function state; must be initialized
 */
void OQS_SHA3_cshake256_inc_finalize(OQS_SHA3_shake256_inc_ctx *state);

/**
 * \brief The cSHAKE-256 squeeze function.
 * Extracts to an output byte array.
 *
 * \param output output buffer
 * \param outlen bytes of outbut buffer
 * \param state The function state; must be initialized
 */
void OQS_SHA3_cshake256_inc_squeeze(uint8_t *output, size_t outlen, OQS_SHA3_shake256_inc_ctx *state);

/**
 * \brief Free the cSHAKE-256 incremental context.
 *
 * \param state The function state; must be initialized
 */
void OQS_SHA3_cshake256_inc_ctx_release(OQS_SHA3_shake256_inc_ctx *state);

/**
 * \brief Copies the state for the cSHAKE-256 incremental hashing API.
 *
 * \warning dest must be allocated. dest must be freed by calling
 * OQS_SHA3_cshake256_inc_ctx_release.
 *
 * \param dest The state to copy into
 * \param src The state to copy from
 */
void OQS_SHA3_cshake256_inc_ctx_clone(OQS_SHA3_shake256_inc_ctx *dest, const OQS_SHA3_shake256_inc_ctx *src);

/**
* \brief Seed a cSHAKE-128 instance and generate pseudo-random output, using a "simplified" customization string.
* Permutes and extracts the state to an output byte array.
* The "simplified" customization string procedure is ad hoc but used in several NIST candidates.
*
* \warning This function has a counter period of 2^16.
*
* \param output The output byte array
* \param outlen The number of output bytes to generate
* \param cstm The 16bit customization integer
* \param input The input seed byte array
* \param inplen The number of seed bytes to process
*/
void OQS_SHA3_cshake128_simple(uint8_t *output, size_t outlen, uint16_t cstm, const uint8_t *input, size_t inplen);

/**
* \brief Seed a cSHAKE-256 instance and generate pseudo-random output, using a "simplified" customization string.
* Permutes and extracts the state to an output byte array.
* The "simplified" customization string procedure is ad hoc but used in several NIST candidates.
*
* \warning This function has a counter period of 2^16.
*
* \param output The output byte array
* \param outlen The number of output bytes to generate
* \param cstm The 16bit customization integer
* \param input The input seed byte array
* \param inplen The number of seed bytes to process
*/
void OQS_SHA3_cshake256_simple(uint8_t *output, size_t outlen, uint16_t cstm, const uint8_t *input, size_t inplen);

#if defined(OQS_USE_AVX2_INSTRUCTIONS) && defined(OQS_USE_AES_INSTRUCTIONS)
/**
 * \brief Seed 4 parallel SHAKE-128 instances, and generate 4 arrays of pseudo-random bytes.
 *
 * Uses a vectorized (AVX2) implementation of SHAKE-128.
 *
 * \warning The output array length must not be zero.
 *
 * \param output0 The first output byte array
 * \param output1 The second output byte array
 * \param output2 The third output byte array
 * \param output3 The fourth output byte array
 * \param outlen The number of output bytes to generate in every output array
 * \param in0 The first input seed byte array
 * \param in1 The second input seed byte array
 * \param in2 The third input seed byte array
 * \param in3 The fourth input seed byte array
 * \param inlen The number of seed bytes to process from every input array
 */
void OQS_SHA3_shake128_4x(uint8_t *output0, uint8_t *output1, uint8_t *output2, uint8_t *output3, size_t outlen, const uint8_t *in0, const uint8_t *in1, const uint8_t *in2, const uint8_t *in3, size_t inlen);

/**
* \brief Seed 4 parallel cSHAKE-128 instances, and generate 4 arrays of pseudo-random output, using a "simplified" customization string.
* Uses a vectorized (AVX2) implementation of cSHAKE-128.
* Permutes and extracts the state to an output byte array.
* The "simplified" customization string procedure is ad hoc but used in several NIST candidates.
*
* \warning This function has a counter period of 2^16.
*
* \param output0 The first output byte array
* \param output1 The second output byte array
* \param output2 The third output byte array
* \param output3 The fourth output byte array
* \param outlen The number of output bytes to generate in every output array
* \param cstm0 The first 16bit customization integer
* \param cstm1 The second 16bit customization integer
* \param cstm2 The third 16bit customization integer
* \param cstm3 The fourth 16bit customization integer
* \param input The input seed byte array
* \param inplen The number of seed bytes to process
*/
void OQS_SHA3_cshake128_simple4x(uint8_t *output0, uint8_t *output1, uint8_t *output2, uint8_t *output3, size_t outlen, uint16_t cstm0, uint16_t cstm1, uint16_t cstm2, uint16_t cstm3, const uint8_t *in, size_t inlen);
#endif

#if defined(__cplusplus)
} // extern "C"
#endif

#endif // OQS_SHA3_H
