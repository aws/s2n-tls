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

#include <openssl/evp.h>
#include <openssl/rsa.h>

#include "error/s2n_errno.h"

#include "stuffer/s2n_stuffer.h"

#include "crypto/s2n_hash.h"
#include "crypto/s2n_rsa_pss.h"
#include "crypto/s2n_rsa_signing.h"
#include "crypto/s2n_pkey.h"

#include "utils/s2n_blob.h"
#include "utils/s2n_safety.h"

static int s2n_hash_alg_to_NID[] = {
    [S2N_HASH_MD5_SHA1] = NID_md5_sha1,
    [S2N_HASH_SHA1]     = NID_sha1,
    [S2N_HASH_SHA224]   = NID_sha224,
    [S2N_HASH_SHA256]   = NID_sha256,
    [S2N_HASH_SHA384]   = NID_sha384,
    [S2N_HASH_SHA512]   = NID_sha512 };

int s2n_hash_NID_type(s2n_hash_algorithm alg, int *out)
{
    switch(alg) {
    case S2N_HASH_MD5_SHA1:
    case S2N_HASH_SHA1:
    case S2N_HASH_SHA224:
    case S2N_HASH_SHA256:
    case S2N_HASH_SHA384:
    case S2N_HASH_SHA512:
        *out = s2n_hash_alg_to_NID[alg];
        break;
    default:
        POSIX_BAIL(S2N_ERR_HASH_INVALID_ALGORITHM);
    }
    return 0;
}

int s2n_rsa_pkcs1v15_sign(const struct s2n_pkey *priv, struct s2n_hash_state *digest, struct s2n_blob *signature)
{
    uint8_t digest_length;
    int NID_type;
    POSIX_GUARD(s2n_hash_digest_size(digest->alg, &digest_length));
    POSIX_GUARD(s2n_hash_NID_type(digest->alg, &NID_type));
    POSIX_ENSURE_LTE(digest_length, S2N_MAX_DIGEST_LEN);

    const s2n_rsa_private_key *key = &priv->key.rsa_key;

    uint8_t digest_out[S2N_MAX_DIGEST_LEN];
    POSIX_GUARD(s2n_hash_digest(digest, digest_out, digest_length));

    unsigned int signature_size = signature->size;
    POSIX_GUARD_OSSL(RSA_sign(NID_type, digest_out, digest_length, signature->data, &signature_size, key->rsa), S2N_ERR_SIGN);
    S2N_ERROR_IF(signature_size > signature->size, S2N_ERR_SIZE_MISMATCH);
    signature->size = signature_size;

    return 0;
}

int s2n_rsa_pkcs1v15_verify(const struct s2n_pkey *pub, struct s2n_hash_state *digest, struct s2n_blob *signature)
{
    uint8_t digest_length;
    int digest_NID_type;
    POSIX_GUARD(s2n_hash_digest_size(digest->alg, &digest_length));
    POSIX_GUARD(s2n_hash_NID_type(digest->alg, &digest_NID_type));
    POSIX_ENSURE_LTE(digest_length, S2N_MAX_DIGEST_LEN);

    const s2n_rsa_public_key *key = &pub->key.rsa_key;

    uint8_t digest_out[S2N_MAX_DIGEST_LEN];
    POSIX_GUARD(s2n_hash_digest(digest, digest_out, digest_length));

    POSIX_GUARD_OSSL(RSA_verify(digest_NID_type, digest_out, digest_length, signature->data, signature->size, key->rsa), S2N_ERR_VERIFY_SIGNATURE);

    return 0;
}

/* this function returns whether RSA PSS signing is supported */
int s2n_is_rsa_pss_signing_supported()
{
    return RSA_PSS_SIGNING_SUPPORTED;
}

#if RSA_PSS_SIGNING_SUPPORTED

const EVP_MD* s2n_hash_alg_to_evp_alg(s2n_hash_algorithm alg)
{
    switch (alg) {
        case S2N_HASH_MD5_SHA1:
            return EVP_md5_sha1();
        case S2N_HASH_SHA1:
            return EVP_sha1();
        case S2N_HASH_SHA224:
            return EVP_sha224();
        case S2N_HASH_SHA256:
            return EVP_sha256();
        case S2N_HASH_SHA384:
            return EVP_sha384();
        case S2N_HASH_SHA512:
            return EVP_sha512();
        default:
            return NULL;
    }
}

/* On some versions of OpenSSL, "EVP_PKEY_CTX_set_signature_md()" is just a macro that casts digest_alg to "void*",
 * which fails to compile when the "-Werror=cast-qual" compiler flag is enabled. So we work around this OpenSSL
 * issue by turning off this compiler check for this one function with a cast through. */
static int s2n_evp_pkey_ctx_set_rsa_signature_digest(EVP_PKEY_CTX *ctx, const EVP_MD* digest_alg)
{
    POSIX_GUARD_OSSL(EVP_PKEY_CTX_set_signature_md(ctx,(EVP_MD*) (uintptr_t) digest_alg), S2N_ERR_INVALID_SIGNATURE_ALGORITHM);
    POSIX_GUARD_OSSL(EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, (EVP_MD*) (uintptr_t) digest_alg), S2N_ERR_INVALID_SIGNATURE_ALGORITHM);
    return 0;
}

static void s2n_evp_pkey_ctx_free(EVP_PKEY_CTX **ctx)
{
    EVP_PKEY_CTX_free(*ctx);
}

int s2n_rsa_pss_sign(const struct s2n_pkey *priv, struct s2n_hash_state *digest, struct s2n_blob *signature_out)
{
    POSIX_ENSURE_REF(priv);

    uint8_t digest_length;
    uint8_t digest_data[S2N_MAX_DIGEST_LEN];
    POSIX_GUARD(s2n_hash_digest_size(digest->alg, &digest_length));
    POSIX_GUARD(s2n_hash_digest(digest, digest_data, digest_length));

    const EVP_MD* digest_alg = s2n_hash_alg_to_evp_alg(digest->alg);
    POSIX_ENSURE_REF(digest_alg);

    /* For more info see: https://www.openssl.org/docs/manmaster/man3/EVP_PKEY_sign.html */
    DEFER_CLEANUP(EVP_PKEY_CTX *ctx  = EVP_PKEY_CTX_new(priv->pkey, NULL), s2n_evp_pkey_ctx_free);
    POSIX_ENSURE_REF(ctx);

    size_t signature_len = signature_out->size;
    POSIX_GUARD_OSSL(EVP_PKEY_sign_init(ctx), S2N_ERR_SIGN);
    POSIX_GUARD_OSSL(EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PSS_PADDING), S2N_ERR_SIGN);
    POSIX_GUARD(s2n_evp_pkey_ctx_set_rsa_signature_digest(ctx, digest_alg));
    POSIX_GUARD_OSSL(EVP_PKEY_CTX_set_rsa_pss_saltlen(ctx, RSA_PSS_SALTLEN_DIGEST), S2N_ERR_SIGN);

    /* Calling EVP_PKEY_sign() with NULL will only update the signature_len parameter so users can validate sizes. */
    POSIX_GUARD_OSSL(EVP_PKEY_sign(ctx, NULL, &signature_len, digest_data, digest_length), S2N_ERR_SIGN);
    S2N_ERROR_IF(signature_len > signature_out->size, S2N_ERR_SIZE_MISMATCH);

    /* Actually sign the the digest */
    POSIX_GUARD_OSSL(EVP_PKEY_sign(ctx, signature_out->data, &signature_len, digest_data, digest_length), S2N_ERR_SIGN);
    signature_out->size = signature_len;

    return 0;
}

int s2n_rsa_pss_verify(const struct s2n_pkey *pub, struct s2n_hash_state *digest, struct s2n_blob *signature_in)
{
    POSIX_ENSURE_REF(pub);

    uint8_t digest_length;
    uint8_t digest_data[S2N_MAX_DIGEST_LEN];
    POSIX_GUARD(s2n_hash_digest_size(digest->alg, &digest_length));
    POSIX_GUARD(s2n_hash_digest(digest, digest_data, digest_length));
    const EVP_MD* digest_alg = s2n_hash_alg_to_evp_alg(digest->alg);
    POSIX_ENSURE_REF(digest_alg);

    /* For more info see: https://www.openssl.org/docs/manmaster/man3/EVP_PKEY_verify.html */
    DEFER_CLEANUP(EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pub->pkey, NULL), s2n_evp_pkey_ctx_free);
    POSIX_ENSURE_REF(ctx);

    POSIX_GUARD_OSSL(EVP_PKEY_verify_init(ctx), S2N_ERR_VERIFY_SIGNATURE);
    POSIX_GUARD_OSSL(EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PSS_PADDING), S2N_ERR_SIGN);
    POSIX_GUARD(s2n_evp_pkey_ctx_set_rsa_signature_digest(ctx, digest_alg));
    POSIX_GUARD_OSSL(EVP_PKEY_verify(ctx, signature_in->data, signature_in->size, digest_data, digest_length), S2N_ERR_VERIFY_SIGNATURE);

    return 0;
}

#else

int s2n_rsa_pss_sign(const struct s2n_pkey *priv, struct s2n_hash_state *digest, struct s2n_blob *signature_out)
{
    POSIX_BAIL(S2N_RSA_PSS_NOT_SUPPORTED);
}

int s2n_rsa_pss_verify(const struct s2n_pkey *pub, struct s2n_hash_state *digest, struct s2n_blob *signature_in)
{
    POSIX_BAIL(S2N_RSA_PSS_NOT_SUPPORTED);
}

#endif
