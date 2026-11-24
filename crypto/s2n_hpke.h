/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * A copy of the License is located at
 *
 *  http://aws.amazon.com/apache2.0
 *
 * or in the "license" file accompanying this file. This file is distributed
 * on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */

#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "stuffer/s2n_stuffer.h"
#include "utils/s2n_blob.h"
#include "utils/s2n_result.h"

/* HPKE (RFC 9180) base mode, limited to the suites that ECH (RFC 9849) uses.
 *
 * Only AWS-LC's EVP_HPKE_* API backs this interface. s2n-tls supports ECH only
 * with AWS-LC, so BoringSSL, which shares the API, is deliberately excluded
 * rather than enabled without being tested. No libcrypto types appear here,
 * so that another backend remains possible.
 */

/* RFC 9180 7.1: the only KEM supported. AWS-LC may offer others. */
#define S2N_HPKE_KEM_X25519_HKDF_SHA256 0x0020
/* RFC 9180 7.2 */
#define S2N_HPKE_KDF_HKDF_SHA256 0x0001
/* RFC 9180 7.3 */
#define S2N_HPKE_AEAD_AES_128_GCM       0x0001
#define S2N_HPKE_AEAD_AES_256_GCM       0x0002
#define S2N_HPKE_AEAD_CHACHA20_POLY1305 0x0003

/* RFC 9180 7.1: Npk, Nenc, and Nsk for DHKEM(X25519, HKDF-SHA256).
 * Size buffers with these, not with the libcrypto's maximums,
 * which grow as the libcrypto adds KEMs. */
#define S2N_HPKE_X25519_PUBLIC_KEY_LEN  32
#define S2N_HPKE_X25519_ENC_LEN         32
#define S2N_HPKE_X25519_PRIVATE_KEY_LEN 32

/* Does not consider FIPS mode. Callers that must not use HPKE in FIPS mode
 * check s2n_is_in_fips_mode() themselves. */
bool s2n_hpke_is_supported(void);
bool s2n_hpke_suite_is_supported(uint16_t kem_id, uint16_t kdf_id, uint16_t aead_id);

struct s2n_hpke_key;
S2N_RESULT s2n_hpke_key_new(struct s2n_hpke_key **key);
S2N_CLEANUP_RESULT s2n_hpke_key_free(struct s2n_hpke_key **key);
S2N_RESULT s2n_hpke_key_generate(struct s2n_hpke_key *key, uint16_t kem_id);
S2N_RESULT s2n_hpke_key_init(struct s2n_hpke_key *key, uint16_t kem_id, const struct s2n_blob *priv);
/* Writes the public key to the start of `out` and sets `out->size` to its length. */
S2N_RESULT s2n_hpke_key_public_key(const struct s2n_hpke_key *key, struct s2n_blob *out);

/* Retained across a HelloRetryRequest: RFC 9849 7.1.1 requires the second
 * ClientHelloOuter to be decrypted with the same HPKE context.
 *
 * Setting up a context that is already set up discards its previous state. */
struct s2n_hpke_ctx;
S2N_RESULT s2n_hpke_ctx_new(struct s2n_hpke_ctx **ctx);
S2N_CLEANUP_RESULT s2n_hpke_ctx_free(struct s2n_hpke_ctx **ctx);

/* `kdf_id`, `aead_id` and `enc` come from the peer, so an unsupported suite
 * or a bad `enc` fails with S2N_ERR_DECRYPT, like a failed open. */
S2N_RESULT s2n_hpke_setup_recipient(struct s2n_hpke_ctx *ctx, const struct s2n_hpke_key *key,
        uint16_t kdf_id, uint16_t aead_id, const struct s2n_blob *enc, const struct s2n_blob *info);
/* Writes `enc` to the start of `enc_out` and sets `enc_out->size` to its length. */
S2N_RESULT s2n_hpke_setup_sender(struct s2n_hpke_ctx *ctx, uint16_t kem_id, uint16_t kdf_id,
        uint16_t aead_id, const struct s2n_blob *peer_public_key, const struct s2n_blob *info,
        struct s2n_blob *enc_out);
/* Test-only: wraps EVP_HPKE_CTX_setup_sender_with_seed_for_testing so the
 * RFC 9180 Appendix A vectors reproduce deterministically. */
S2N_RESULT s2n_hpke_setup_sender_with_seed(struct s2n_hpke_ctx *ctx, uint16_t kem_id,
        uint16_t kdf_id, uint16_t aead_id, const struct s2n_blob *peer_public_key,
        const struct s2n_blob *info, const struct s2n_blob *seed, struct s2n_blob *enc_out);

/* Appends the ciphertext or plaintext to `out`, which grows if it is growable.
 * `in` must not overlap the unwritten part of `out`. Seal needs a sender context
 * and open a recipient one; otherwise they fail with S2N_ERR_INVALID_STATE. */
S2N_RESULT s2n_hpke_seal(struct s2n_hpke_ctx *ctx, const struct s2n_blob *aad,
        const struct s2n_blob *in, struct s2n_stuffer *out);
S2N_RESULT s2n_hpke_open(struct s2n_hpke_ctx *ctx, const struct s2n_blob *aad,
        const struct s2n_blob *in, struct s2n_stuffer *out);
S2N_RESULT s2n_hpke_max_overhead(const struct s2n_hpke_ctx *ctx, uint16_t *out);
