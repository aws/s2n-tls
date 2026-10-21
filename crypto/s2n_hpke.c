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

#include "crypto/s2n_hpke.h"

#include <openssl/crypto.h>

#include "utils/s2n_mem.h"
#include "utils/s2n_safety.h"

/* S2N_LIBCRYPTO_SUPPORTS_HPKE will be auto-detected and #defined if
 * ./tests/features/S2N_LIBCRYPTO_SUPPORTS_HPKE.c successfully compiles.
 * BoringSSL passes the probe too, so also require AWS-LC: see s2n_hpke.h.
 */
#if defined(S2N_LIBCRYPTO_SUPPORTS_HPKE) && defined(OPENSSL_IS_AWSLC)
    #define S2N_HPKE_AWSLC_BACKEND 1
    #include <openssl/hpke.h>
#endif

bool s2n_hpke_is_supported(void)
{
#if defined(S2N_HPKE_AWSLC_BACKEND)
    return true;
#else
    return false;
#endif
}

bool s2n_hpke_suite_is_supported(uint16_t kem_id, uint16_t kdf_id, uint16_t aead_id) /* NOLINT(bugprone-easily-swappable-parameters) */
{
    if (!s2n_hpke_is_supported()) {
        return false;
    }
    /* Accept only what ECH needs, not every suite the libcrypto offers */
    if (kem_id != S2N_HPKE_KEM_X25519_HKDF_SHA256 || kdf_id != S2N_HPKE_KDF_HKDF_SHA256) {
        return false;
    }
    switch (aead_id) {
        case S2N_HPKE_AEAD_AES_128_GCM:
        case S2N_HPKE_AEAD_AES_256_GCM:
        case S2N_HPKE_AEAD_CHACHA20_POLY1305:
            return true;
        default:
            return false;
    }
}

#if defined(S2N_HPKE_AWSLC_BACKEND)

/* EVP_HPKE_KEY and EVP_HPKE_CTX are only ever allocated by the libcrypto.
 * EVP_HPKE_KEY's size changed when AWS-LC added ML-KEM KEMs, so embedding
 * it here would tie s2n-tls to one version of the AWS-LC headers. */
struct s2n_hpke_key {
    EVP_HPKE_KEY *key;
};

typedef enum {
    S2N_HPKE_ROLE_NONE = 0,
    S2N_HPKE_ROLE_SENDER,
    S2N_HPKE_ROLE_RECIPIENT,
} s2n_hpke_role;

struct s2n_hpke_ctx {
    EVP_HPKE_CTX *ctx;
    /* A failed setup can leave the libcrypto context unusable, so track
     * whether the last setup succeeded, and for which role. A wrong-role
     * seal or open is then a caller error, not a decryption failure. */
    s2n_hpke_role role;
};

static S2N_RESULT s2n_hpke_get_kem(uint16_t kem_id, const EVP_HPKE_KEM **kem)
{
    RESULT_ENSURE_REF(kem);
    RESULT_ENSURE(kem_id == S2N_HPKE_KEM_X25519_HKDF_SHA256, S2N_ERR_INVALID_ARGUMENT);
    *kem = EVP_hpke_x25519_hkdf_sha256();
    RESULT_ENSURE_REF(*kem);
    return S2N_RESULT_OK;
}

/* Callers check the suite with s2n_hpke_suite_is_supported first,
 * because the error depends on who chose it */
static S2N_RESULT s2n_hpke_get_kdf_aead(uint16_t kdf_id, uint16_t aead_id,
        const EVP_HPKE_KDF **kdf, const EVP_HPKE_AEAD **aead)
{
    RESULT_ENSURE_REF(kdf);
    RESULT_ENSURE_REF(aead);
    RESULT_ENSURE(kdf_id == S2N_HPKE_KDF_HKDF_SHA256, S2N_ERR_SAFETY);

    *kdf = EVP_hpke_hkdf_sha256();
    switch (aead_id) {
        case S2N_HPKE_AEAD_AES_128_GCM:
            *aead = EVP_hpke_aes_128_gcm();
            break;
        case S2N_HPKE_AEAD_AES_256_GCM:
            *aead = EVP_hpke_aes_256_gcm();
            break;
        case S2N_HPKE_AEAD_CHACHA20_POLY1305:
            *aead = EVP_hpke_chacha20_poly1305();
            break;
        default:
            RESULT_BAIL(S2N_ERR_SAFETY);
    }
    RESULT_ENSURE_REF(*kdf);
    RESULT_ENSURE_REF(*aead);
    return S2N_RESULT_OK;
}

S2N_RESULT s2n_hpke_key_new(struct s2n_hpke_key **key)
{
    RESULT_ENSURE_REF(key);
    RESULT_ENSURE(*key == NULL, S2N_ERR_SAFETY);

    DEFER_CLEANUP(struct s2n_blob mem = { 0 }, s2n_free);
    RESULT_GUARD_POSIX(s2n_alloc(&mem, sizeof(struct s2n_hpke_key)));
    RESULT_GUARD_POSIX(s2n_blob_zero(&mem));
    struct s2n_hpke_key *new_key = (struct s2n_hpke_key *) (void *) mem.data;

    new_key->key = EVP_HPKE_KEY_new();
    RESULT_ENSURE(new_key->key != NULL, S2N_ERR_ALLOC);

    *key = new_key;
    ZERO_TO_DISABLE_DEFER_CLEANUP(mem);
    return S2N_RESULT_OK;
}

S2N_CLEANUP_RESULT s2n_hpke_key_free(struct s2n_hpke_key **key)
{
    RESULT_ENSURE_REF(key);
    if (*key == NULL) {
        return S2N_RESULT_OK;
    }
    /* EVP_HPKE_KEY_free cleanses the private key */
    EVP_HPKE_KEY_free((*key)->key);
    (*key)->key = NULL;
    RESULT_GUARD_POSIX(s2n_free_object((uint8_t **) key, sizeof(struct s2n_hpke_key)));
    return S2N_RESULT_OK;
}

S2N_RESULT s2n_hpke_key_generate(struct s2n_hpke_key *key, uint16_t kem_id)
{
    RESULT_ENSURE_REF(key);
    RESULT_ENSURE_REF(key->key);
    const EVP_HPKE_KEM *kem = NULL;
    RESULT_GUARD(s2n_hpke_get_kem(kem_id, &kem));
    /* Some AWS-LC releases zero the key here without freeing or cleansing
     * the key material it already holds. Cleaning up an empty key is safe. */
    EVP_HPKE_KEY_cleanup(key->key);
    RESULT_GUARD_OSSL(EVP_HPKE_KEY_generate(key->key, kem), S2N_ERR_KEY_INIT);
    return S2N_RESULT_OK;
}

S2N_RESULT s2n_hpke_key_init(struct s2n_hpke_key *key, uint16_t kem_id, const struct s2n_blob *priv)
{
    RESULT_ENSURE_REF(key);
    RESULT_ENSURE_REF(key->key);
    RESULT_ENSURE_REF(priv);
    const EVP_HPKE_KEM *kem = NULL;
    RESULT_GUARD(s2n_hpke_get_kem(kem_id, &kem));
    RESULT_ENSURE(priv->size == S2N_HPKE_X25519_PRIVATE_KEY_LEN, S2N_ERR_INVALID_ARGUMENT);
    /* As in s2n_hpke_key_generate */
    EVP_HPKE_KEY_cleanup(key->key);
    RESULT_GUARD_OSSL(EVP_HPKE_KEY_init(key->key, kem, priv->data, priv->size), S2N_ERR_KEY_INIT);
    return S2N_RESULT_OK;
}

S2N_RESULT s2n_hpke_key_public_key(const struct s2n_hpke_key *key, struct s2n_blob *out)
{
    RESULT_ENSURE_REF(key);
    RESULT_ENSURE_REF(key->key);
    RESULT_ENSURE_REF(out);
    RESULT_ENSURE(EVP_HPKE_KEY_kem(key->key) != NULL, S2N_ERR_INVALID_STATE);
    RESULT_ENSURE(out->size >= S2N_HPKE_X25519_PUBLIC_KEY_LEN, S2N_ERR_INSUFFICIENT_MEM_SIZE);

    size_t out_len = 0;
    RESULT_GUARD_OSSL(EVP_HPKE_KEY_public_key(key->key, out->data, &out_len, out->size),
            S2N_ERR_SAFETY);
    RESULT_ENSURE(out_len == S2N_HPKE_X25519_PUBLIC_KEY_LEN, S2N_ERR_SAFETY);
    out->size = out_len;
    return S2N_RESULT_OK;
}

S2N_RESULT s2n_hpke_ctx_new(struct s2n_hpke_ctx **ctx)
{
    RESULT_ENSURE_REF(ctx);
    RESULT_ENSURE(*ctx == NULL, S2N_ERR_SAFETY);

    DEFER_CLEANUP(struct s2n_blob mem = { 0 }, s2n_free);
    RESULT_GUARD_POSIX(s2n_alloc(&mem, sizeof(struct s2n_hpke_ctx)));
    RESULT_GUARD_POSIX(s2n_blob_zero(&mem));
    struct s2n_hpke_ctx *new_ctx = (struct s2n_hpke_ctx *) (void *) mem.data;

    new_ctx->ctx = EVP_HPKE_CTX_new();
    RESULT_ENSURE(new_ctx->ctx != NULL, S2N_ERR_ALLOC);

    *ctx = new_ctx;
    ZERO_TO_DISABLE_DEFER_CLEANUP(mem);
    return S2N_RESULT_OK;
}

S2N_CLEANUP_RESULT s2n_hpke_ctx_free(struct s2n_hpke_ctx **ctx)
{
    RESULT_ENSURE_REF(ctx);
    if (*ctx == NULL) {
        return S2N_RESULT_OK;
    }
    EVP_HPKE_CTX_free((*ctx)->ctx);
    (*ctx)->ctx = NULL;
    RESULT_GUARD_POSIX(s2n_free_object((uint8_t **) ctx, sizeof(struct s2n_hpke_ctx)));
    return S2N_RESULT_OK;
}

static S2N_RESULT s2n_hpke_ctx_reset(struct s2n_hpke_ctx *ctx)
{
    RESULT_ENSURE_REF(ctx);
    RESULT_ENSURE_REF(ctx->ctx);
    /* The libcrypto's setup functions zero the context without cleaning it up */
    ctx->role = S2N_HPKE_ROLE_NONE;
    EVP_HPKE_CTX_cleanup(ctx->ctx);
    EVP_HPKE_CTX_zero(ctx->ctx);
    return S2N_RESULT_OK;
}

S2N_RESULT s2n_hpke_setup_recipient(struct s2n_hpke_ctx *ctx, const struct s2n_hpke_key *key,
        uint16_t kdf_id, uint16_t aead_id, const struct s2n_blob *enc, const struct s2n_blob *info)
{
    RESULT_GUARD(s2n_hpke_ctx_reset(ctx));
    RESULT_ENSURE_REF(key);
    RESULT_ENSURE_REF(key->key);
    RESULT_ENSURE_REF(enc);
    RESULT_ENSURE_REF(info);

    const EVP_HPKE_KEM *key_kem = EVP_HPKE_KEY_kem(key->key);
    RESULT_ENSURE(key_kem != NULL, S2N_ERR_INVALID_STATE);

    /* The KDF, AEAD and enc are peer-controlled, so a bad one is
     * a decryption failure, not a caller error */
    RESULT_ENSURE(s2n_hpke_suite_is_supported(EVP_HPKE_KEM_id(key_kem), kdf_id, aead_id), S2N_ERR_DECRYPT);
    RESULT_ENSURE(enc->size == S2N_HPKE_X25519_ENC_LEN, S2N_ERR_DECRYPT);
    const EVP_HPKE_KDF *kdf = NULL;
    const EVP_HPKE_AEAD *aead = NULL;
    RESULT_GUARD(s2n_hpke_get_kdf_aead(kdf_id, aead_id, &kdf, &aead));

    /**
     *= https://www.rfc-editor.org/rfc/rfc9180#section-7.1.4
     *# In particular, recipients MUST
     *# check whether the Diffie-Hellman shared secret is the all-zero value
     *# and abort if so.
     *
     * The libcrypto's X25519 performs the check, and setup fails.
     */
    RESULT_GUARD_OSSL(EVP_HPKE_CTX_setup_recipient(ctx->ctx, key->key, kdf, aead,
                              enc->data, enc->size, info->data, info->size),
            S2N_ERR_DECRYPT);
    ctx->role = S2N_HPKE_ROLE_RECIPIENT;
    return S2N_RESULT_OK;
}

static S2N_RESULT s2n_hpke_setup_sender_impl(struct s2n_hpke_ctx *ctx, uint16_t kem_id,
        uint16_t kdf_id, uint16_t aead_id, const struct s2n_blob *peer_public_key,
        const struct s2n_blob *info, const struct s2n_blob *seed, struct s2n_blob *enc_out)
{
    RESULT_GUARD(s2n_hpke_ctx_reset(ctx));
    RESULT_ENSURE_REF(peer_public_key);
    RESULT_ENSURE_REF(info);
    RESULT_ENSURE_REF(enc_out);

    RESULT_ENSURE(s2n_hpke_suite_is_supported(kem_id, kdf_id, aead_id), S2N_ERR_INVALID_ARGUMENT);
    const EVP_HPKE_KEM *kem = NULL;
    RESULT_GUARD(s2n_hpke_get_kem(kem_id, &kem));
    const EVP_HPKE_KDF *kdf = NULL;
    const EVP_HPKE_AEAD *aead = NULL;
    RESULT_GUARD(s2n_hpke_get_kdf_aead(kdf_id, aead_id, &kdf, &aead));
    RESULT_ENSURE(peer_public_key->size == S2N_HPKE_X25519_PUBLIC_KEY_LEN, S2N_ERR_INVALID_ARGUMENT);
    RESULT_ENSURE(enc_out->size >= S2N_HPKE_X25519_ENC_LEN, S2N_ERR_INSUFFICIENT_MEM_SIZE);

    /**
     *= https://www.rfc-editor.org/rfc/rfc9180#section-7.1.4
     *# For X25519 and X448, public keys and Diffie-Hellman outputs MUST be
     *# validated as described in [RFC7748].
     *
     * The libcrypto's X25519 rejects an all-zero output, and setup fails.
     */
    size_t enc_len = 0;
    if (seed) {
        RESULT_GUARD_OSSL(EVP_HPKE_CTX_setup_sender_with_seed_for_testing(ctx->ctx,
                                  enc_out->data, &enc_len, enc_out->size, kem, kdf, aead,
                                  peer_public_key->data, peer_public_key->size,
                                  info->data, info->size, seed->data, seed->size),
                S2N_ERR_ENCRYPT);
    } else {
        RESULT_GUARD_OSSL(EVP_HPKE_CTX_setup_sender(ctx->ctx,
                                  enc_out->data, &enc_len, enc_out->size, kem, kdf, aead,
                                  peer_public_key->data, peer_public_key->size,
                                  info->data, info->size),
                S2N_ERR_ENCRYPT);
    }
    RESULT_ENSURE(enc_len == S2N_HPKE_X25519_ENC_LEN, S2N_ERR_SAFETY);
    enc_out->size = enc_len;
    ctx->role = S2N_HPKE_ROLE_SENDER;
    return S2N_RESULT_OK;
}

S2N_RESULT s2n_hpke_setup_sender(struct s2n_hpke_ctx *ctx, uint16_t kem_id, uint16_t kdf_id,
        uint16_t aead_id, const struct s2n_blob *peer_public_key, const struct s2n_blob *info,
        struct s2n_blob *enc_out)
{
    RESULT_GUARD(s2n_hpke_setup_sender_impl(ctx, kem_id, kdf_id, aead_id, peer_public_key,
            info, NULL, enc_out));
    return S2N_RESULT_OK;
}

S2N_RESULT s2n_hpke_setup_sender_with_seed(struct s2n_hpke_ctx *ctx, uint16_t kem_id,
        uint16_t kdf_id, uint16_t aead_id, const struct s2n_blob *peer_public_key,
        const struct s2n_blob *info, const struct s2n_blob *seed, struct s2n_blob *enc_out)
{
    RESULT_ENSURE(s2n_in_unit_test(), S2N_ERR_NOT_IN_UNIT_TEST);
    RESULT_ENSURE_REF(seed);
    RESULT_GUARD(s2n_hpke_setup_sender_impl(ctx, kem_id, kdf_id, aead_id, peer_public_key,
            info, seed, enc_out));
    return S2N_RESULT_OK;
}

S2N_RESULT s2n_hpke_max_overhead(const struct s2n_hpke_ctx *ctx, uint16_t *out)
{
    RESULT_ENSURE_REF(ctx);
    RESULT_ENSURE_REF(ctx->ctx);
    RESULT_ENSURE_REF(out);
    RESULT_ENSURE(ctx->role != S2N_HPKE_ROLE_NONE, S2N_ERR_INVALID_STATE);

    /* EVP_HPKE_CTX_max_overhead only accepts a sender context */
    const EVP_HPKE_AEAD *aead = EVP_HPKE_CTX_aead(ctx->ctx);
    RESULT_ENSURE_REF(aead);
    const EVP_AEAD *evp_aead = EVP_HPKE_AEAD_aead(aead);
    RESULT_ENSURE_REF(evp_aead);
    size_t overhead = EVP_AEAD_max_overhead(evp_aead);
    RESULT_ENSURE_LTE(overhead, UINT16_MAX);
    *out = overhead;
    return S2N_RESULT_OK;
}

S2N_RESULT s2n_hpke_seal(struct s2n_hpke_ctx *ctx, const struct s2n_blob *aad,
        const struct s2n_blob *in, struct s2n_stuffer *out)
{
    RESULT_ENSURE_REF(ctx);
    RESULT_ENSURE_REF(aad);
    RESULT_ENSURE_REF(in);
    RESULT_ENSURE_REF(out);
    RESULT_ENSURE(ctx->role == S2N_HPKE_ROLE_SENDER, S2N_ERR_INVALID_STATE);
    uint16_t overhead = 0;
    RESULT_GUARD(s2n_hpke_max_overhead(ctx, &overhead));

    uint32_t max_out_len = 0;
    RESULT_GUARD_POSIX(s2n_add_overflow(in->size, overhead, &max_out_len));
    RESULT_GUARD_POSIX(s2n_stuffer_reserve_space(out, max_out_len));
    uint8_t *out_data = out->blob.data + out->write_cursor;

    size_t out_len = 0;
    RESULT_GUARD_OSSL(EVP_HPKE_CTX_seal(ctx->ctx, out_data, &out_len, max_out_len,
                              in->data, in->size, aad->data, aad->size),
            S2N_ERR_ENCRYPT);
    RESULT_ENSURE_LTE(out_len, max_out_len);
    RESULT_GUARD_POSIX(s2n_stuffer_skip_write(out, out_len));
    return S2N_RESULT_OK;
}

S2N_RESULT s2n_hpke_open(struct s2n_hpke_ctx *ctx, const struct s2n_blob *aad,
        const struct s2n_blob *in, struct s2n_stuffer *out)
{
    RESULT_ENSURE_REF(ctx);
    RESULT_ENSURE_REF(aad);
    RESULT_ENSURE_REF(in);
    RESULT_ENSURE_REF(out);
    RESULT_ENSURE(ctx->role == S2N_HPKE_ROLE_RECIPIENT, S2N_ERR_INVALID_STATE);
    uint16_t overhead = 0;
    RESULT_GUARD(s2n_hpke_max_overhead(ctx, &overhead));
    /* Reject a ciphertext too short to hold the tag before touching `out` */
    RESULT_ENSURE(in->size >= overhead, S2N_ERR_DECRYPT);

    /* The plaintext is never longer than the ciphertext without its tag */
    const uint32_t max_out_len = in->size - overhead;
    RESULT_GUARD_POSIX(s2n_stuffer_reserve_space(out, max_out_len));
    uint8_t *out_data = out->blob.data + out->write_cursor;

    size_t out_len = 0;
    RESULT_GUARD_OSSL(EVP_HPKE_CTX_open(ctx->ctx, out_data, &out_len, max_out_len,
                              in->data, in->size, aad->data, aad->size),
            S2N_ERR_DECRYPT);
    RESULT_ENSURE_LTE(out_len, max_out_len);
    RESULT_GUARD_POSIX(s2n_stuffer_skip_write(out, out_len));
    return S2N_RESULT_OK;
}

#else

S2N_RESULT s2n_hpke_key_new(struct s2n_hpke_key **key)
{
    RESULT_BAIL(S2N_ERR_UNIMPLEMENTED);
}

S2N_CLEANUP_RESULT s2n_hpke_key_free(struct s2n_hpke_key **key)
{
    /* s2n_hpke_key_new never succeeds, so there is nothing to free */
    RESULT_ENSURE_REF(key);
    RESULT_ENSURE(*key == NULL, S2N_ERR_SAFETY);
    return S2N_RESULT_OK;
}

S2N_RESULT s2n_hpke_key_generate(struct s2n_hpke_key *key, uint16_t kem_id)
{
    RESULT_BAIL(S2N_ERR_UNIMPLEMENTED);
}

S2N_RESULT s2n_hpke_key_init(struct s2n_hpke_key *key, uint16_t kem_id, const struct s2n_blob *priv)
{
    RESULT_BAIL(S2N_ERR_UNIMPLEMENTED);
}

S2N_RESULT s2n_hpke_key_public_key(const struct s2n_hpke_key *key, struct s2n_blob *out)
{
    RESULT_BAIL(S2N_ERR_UNIMPLEMENTED);
}

S2N_RESULT s2n_hpke_ctx_new(struct s2n_hpke_ctx **ctx)
{
    RESULT_BAIL(S2N_ERR_UNIMPLEMENTED);
}

S2N_CLEANUP_RESULT s2n_hpke_ctx_free(struct s2n_hpke_ctx **ctx)
{
    /* s2n_hpke_ctx_new never succeeds, so there is nothing to free */
    RESULT_ENSURE_REF(ctx);
    RESULT_ENSURE(*ctx == NULL, S2N_ERR_SAFETY);
    return S2N_RESULT_OK;
}

S2N_RESULT s2n_hpke_setup_recipient(struct s2n_hpke_ctx *ctx, const struct s2n_hpke_key *key,
        uint16_t kdf_id, uint16_t aead_id, const struct s2n_blob *enc, const struct s2n_blob *info) /* NOLINT(bugprone-easily-swappable-parameters) */
{
    RESULT_BAIL(S2N_ERR_UNIMPLEMENTED);
}

S2N_RESULT s2n_hpke_setup_sender(struct s2n_hpke_ctx *ctx, uint16_t kem_id, uint16_t kdf_id,   /* NOLINT(bugprone-easily-swappable-parameters) */
        uint16_t aead_id, const struct s2n_blob *peer_public_key, const struct s2n_blob *info, /* NOLINT(bugprone-easily-swappable-parameters) */
        struct s2n_blob *enc_out)
{
    RESULT_BAIL(S2N_ERR_UNIMPLEMENTED);
}

S2N_RESULT s2n_hpke_setup_sender_with_seed(struct s2n_hpke_ctx *ctx, uint16_t kem_id, /* NOLINT(bugprone-easily-swappable-parameters) */
        uint16_t kdf_id, uint16_t aead_id, const struct s2n_blob *peer_public_key,    /* NOLINT(bugprone-easily-swappable-parameters) */
        const struct s2n_blob *info, const struct s2n_blob *seed, struct s2n_blob *enc_out)
{
    RESULT_BAIL(S2N_ERR_UNIMPLEMENTED);
}

S2N_RESULT s2n_hpke_seal(struct s2n_hpke_ctx *ctx, const struct s2n_blob *aad, /* NOLINT(bugprone-easily-swappable-parameters) */
        const struct s2n_blob *in, struct s2n_stuffer *out)
{
    RESULT_BAIL(S2N_ERR_UNIMPLEMENTED);
}

S2N_RESULT s2n_hpke_open(struct s2n_hpke_ctx *ctx, const struct s2n_blob *aad, /* NOLINT(bugprone-easily-swappable-parameters) */
        const struct s2n_blob *in, struct s2n_stuffer *out)
{
    RESULT_BAIL(S2N_ERR_UNIMPLEMENTED);
}

S2N_RESULT s2n_hpke_max_overhead(const struct s2n_hpke_ctx *ctx, uint16_t *out)
{
    RESULT_BAIL(S2N_ERR_UNIMPLEMENTED);
}

#endif
