// SPDX-License-Identifier: MIT

#ifndef SHA2_H
#define SHA2_H

#include <stddef.h>
#include <stdint.h>

#define PQC_SHA256CTX_BYTES 40
#define PQC_SHA512CTX_BYTES 72

typedef struct {
	uint8_t *ctx;
} sha256ctx;
#define sha256_inc_init oqs_sha2_sha256_inc_init
#define sha256_inc_ctx_clone oqs_sha2_sha256_inc_ctx_clone
#define sha256_inc_ctx_release oqs_sha2_sha256_inc_ctx_release
#define sha256_inc_blocks oqs_sha2_sha256_inc_blocks
#define sha256_inc_finalize oqs_sha2_sha256_inc_finalize
#define sha256 OQS_SHA2_sha256

typedef struct {
	uint8_t *ctx;
} sha512ctx;
#define sha512_inc_init oqs_sha2_sha512_inc_init
#define sha512_inc_ctx_clone oqs_sha2_sha512_inc_ctx_clone
#define sha512_inc_ctx_release oqs_sha2_sha512_inc_ctx_release
#define sha512_inc_blocks oqs_sha2_sha512_inc_blocks
#define sha512_inc_finalize oqs_sha2_sha512_inc_finalize
#define sha512 OQS_SHA2_sha512

/**
 * \brief Process a message with SHA-256 and return the hash code in the output byte array.
 *
 * \warning The output array must be at least 32 bytes in length.
 *
 * \param output The output byte array
 * \param input The message input byte array
 * \param inplen The number of message bytes to process
 */
void OQS_SHA2_sha256(uint8_t *output, const uint8_t *input, size_t inplen);

/** Data structure for the state of the SHA-256 incremental hashing API. */
typedef struct {
	/** Internal state */
	void *ctx;
} OQS_SHA2_sha256_ctx;

/**
 * \brief Allocate and initialize the state for the SHA-256 incremental hashing API.
 *
 * \warning The state must be released by OQS_SHA2_sha256_inc_finalize
 * or OQS_SHA2_sha256_inc_ctx_release.
 *
 * \param state Pointer to the state
 */
void OQS_SHA2_sha256_inc_init(OQS_SHA2_sha256_ctx *state);

/**
 * \brief Duplicate state for the SHA-256 incremental hashing API.
 *
 * \warning dest must be allocated by the caller. Caller is responsible
 * for releasing dest by calling either OQS_SHA3_sha3_256_inc_finalize or
 * OQS_SHA3_sha3_256_inc_ctx_release.
 *
 * \param dest The function state to copy into; must be initialized
 * \param src The function state to copy; must be initialized
 */
void OQS_SHA2_sha256_inc_ctx_clone(OQS_SHA2_sha256_ctx *dest, const OQS_SHA2_sha256_ctx *src);

/**
 * \brief Process blocks with SHA-256 and update the state.
 *
 * \warning The state must be initialized by OQS_SHA2_sha256_inc_init or OQS_SHA2_sha256_inc_ctx_clone.
 *
 * \param state The state to update
 * \param in Message input byte array
 * \param inblocks The number of blocks of message bytes to process
 */
void OQS_SHA2_sha256_inc_blocks(OQS_SHA2_sha256_ctx *state, const uint8_t *in, size_t inblocks);

/**
 * \brief Process more message bytes with SHA-256 and return the hash code in the output byte array.
 *
 * \warning The output array must be at least 32 bytes in length. The state is
 * deallocated by this function and can not be used again after calling
 * this function without calling OQS_SHA2_sha256_inc_init again.
 *
 * \param out The output byte array
 * \param state The state
 * \param in Additional message input byte array
 * \param inlen The number of additional message bytes to process
 */
void OQS_SHA2_sha256_inc_finalize(uint8_t *out, OQS_SHA2_sha256_ctx *state, const uint8_t *in, size_t inlen);

/**
 * \brief Destroy state.
 *
 * \warning The state is deallocated by this function and can not be used again after calling
 * this function without calling OQS_SHA2_sha256_inc_init again.
 *
 * \param state The state
 */
void OQS_SHA2_sha256_inc_ctx_release(OQS_SHA2_sha256_ctx *state);

/**
 * \brief Process a message with SHA-384 and return the hash code in the output byte array.
 *
 * \warning The output array must be at least 48 bytes in length.
 *
 * \param output The output byte array
 * \param input The message input byte array
 * \param inplen The number of message bytes to process
 */
void OQS_SHA2_sha384(uint8_t *output, const uint8_t *input, size_t inplen);

/** Data structure for the state of the SHA-384 incremental hashing API. */
typedef struct {
	/** Internal state. */
	void *ctx;
} OQS_SHA2_sha384_ctx;

/**
 * \brief Allocate and initialize the state for the SHA-384 incremental hashing API.
 *
 * \warning The state must be released by OQS_SHA2_sha384_inc_finalize
 * or OQS_SHA2_sha384_inc_ctx_release.
 *
 * \param state Pointer to the state
 */
void OQS_SHA2_sha384_inc_init(OQS_SHA2_sha384_ctx *state);

/**
 * \brief Duplicate state for the SHA-384 incremental hashing API.
 *
 * \warning dest must be allocated by the caller. Caller is responsible
 * for releasing dest by calling either OQS_SHA3_sha3_384_inc_finalize or
 * OQS_SHA3_sha3_384_inc_ctx_release.
 *
 * \param dest The function state to copy into; must be initialized
 * \param src The function state to copy; must be initialized
 */
void OQS_SHA2_sha384_inc_ctx_clone(OQS_SHA2_sha384_ctx *dest, const OQS_SHA2_sha384_ctx *src);

/**
 * \brief Process blocks with SHA-384 and update the state.
 *
 * \warning The state must be initialized by OQS_SHA2_sha384_inc_init or OQS_SHA2_sha384_inc_ctx_clone.
 *
 * \param state The state to update
 * \param in Message input byte array
 * \param inblocks The number of blocks of message bytes to process
 */
void OQS_SHA2_sha384_inc_blocks(OQS_SHA2_sha384_ctx *state, const uint8_t *in, size_t inblocks);

/**
 * \brief Process more message bytes with SHA-384 and return the hash code in the output byte array.
 *
 * \warning The output array must be at least 48 bytes in length. The state is
 * deallocated by this function and can not be used again after calling
 * this function without calling OQS_SHA2_sha384_inc_init again.
 *
 * \param out The output byte array
 * \param state The state
 * \param in Additional message input byte array
 * \param inlen The number of additional message bytes to process
 */
void OQS_SHA2_sha384_inc_finalize(uint8_t *out, OQS_SHA2_sha384_ctx *state, const uint8_t *in, size_t inlen);

/**
 * \brief Destroy state.
 *
 * \warning The state is deallocated by this function and can not be used again after calling
 * this function without calling OQS_SHA2_sha384_inc_init again.
 *
 * \param state The state
 */
void OQS_SHA2_sha384_inc_ctx_release(OQS_SHA2_sha384_ctx *state);

/**
 * \brief Process a message with SHA-512 and return the hash code in the output byte array.
 *
 * \warning The output array must be at least 64 bytes in length.
 *
 * \param output The output byte array
 * \param input The message input byte array
 * \param inplen The number of message bytes to process
 */
void OQS_SHA2_sha512(uint8_t *output, const uint8_t *input, size_t inplen);

/** Data structure for the state of the SHA-512 incremental hashing API. */
typedef struct {
	/** Internal state. */
	void *ctx;
} OQS_SHA2_sha512_ctx;

/**
 * \brief Allocate and initialize the state for the SHA-512 incremental hashing API.
 *
 * \warning The state must be released by OQS_SHA2_sha512_inc_finalize
 * or OQS_SHA2_sha512_inc_ctx_release.
 *
 * \param state Pointer to the state
 */
void OQS_SHA2_sha512_inc_init(OQS_SHA2_sha512_ctx *state);

/**
 * \brief Duplicate state for the SHA-512 incremental hashing API.
 *
 * \warning dest must be allocated by the caller. Caller is responsible
 * for releasing dest by calling either OQS_SHA3_sha3_512_inc_finalize or
 * OQS_SHA3_sha3_512_inc_ctx_release.
 *
 * \param dest The function state to copy into; must be initialized
 * \param src The function state to copy; must be initialized
 */
void OQS_SHA2_sha512_inc_ctx_clone(OQS_SHA2_sha512_ctx *dest, const OQS_SHA2_sha512_ctx *src);

/**
 * \brief Process blocks with SHA-512 and update the state.
 *
 * \warning The state must be initialized by OQS_SHA2_sha512_inc_init or OQS_SHA2_sha512_inc_ctx_clone.
 *
 * \param state The state to update
 * \param in Message input byte array
 * \param inblocks The number of blocks of message bytes to process
 */
void OQS_SHA2_sha512_inc_blocks(OQS_SHA2_sha512_ctx *state, const uint8_t *in, size_t inblocks);

/**
 * \brief Process more message bytes with SHA-512 and return the hash code in the output byte array.
 *
 * \warning The output array must be at least 64 bytes in length. The state is
 * deallocated by this function and can not be used again after calling
 * this function without calling OQS_SHA2_sha512_inc_init again.
 *
 * \param out The output byte array
 * \param state The state
 * \param in Additional message input byte array
 * \param inlen The number of additional message bytes to process
 */
void OQS_SHA2_sha512_inc_finalize(uint8_t *out, OQS_SHA2_sha512_ctx *state, const uint8_t *in, size_t inlen);

/**
 * \brief Destroy state.
 *
 * \warning The state is deallocated by this function and can not be used again after calling
 * this function without calling OQS_SHA2_sha512_inc_init again.
 *
 * \param state The state
 */
void OQS_SHA2_sha512_inc_ctx_release(OQS_SHA2_sha512_ctx *state);

#endif
