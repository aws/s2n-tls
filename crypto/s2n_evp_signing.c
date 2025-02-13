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

#include "crypto/s2n_evp_signing.h"

#include "crypto/s2n_evp.h"
#include "crypto/s2n_fips.h"
#include "crypto/s2n_pkey.h"
#include "crypto/s2n_rsa_pss.h"
#include "error/s2n_errno.h"
#include "tls/s2n_signature_algorithms.h"
#include "utils/s2n_safety.h"

DEFINE_POINTER_CLEANUP_FUNC(EVP_PKEY_CTX *, EVP_PKEY_CTX_free);

/*
 * FIPS 140-3 requires that we don't pass raw digest bytes to the libcrypto signing methods.
 * In order to do that, we need to use signing methods that both calculate the digest and
 * perform the signature.
 */

static S2N_RESULT s2n_evp_md_ctx_set_pkey_ctx(EVP_MD_CTX *ctx, EVP_PKEY_CTX *pctx)
{
#ifdef S2N_LIBCRYPTO_SUPPORTS_EVP_MD_CTX_SET_PKEY_CTX
    EVP_MD_CTX_set_pkey_ctx(ctx, pctx);
    return S2N_RESULT_OK;
#else
    RESULT_BAIL(S2N_ERR_UNIMPLEMENTED);
#endif
}

static S2N_RESULT s2n_evp_pkey_set_rsa_pss_saltlen(EVP_PKEY_CTX *pctx)
{
#if defined(S2N_LIBCRYPTO_SUPPORTS_RSA_PSS_SIGNING)
    RESULT_GUARD_OSSL(EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, RSA_PSS_SALTLEN_DIGEST), S2N_ERR_PKEY_CTX_INIT);
    return S2N_RESULT_OK;
#else
    RESULT_BAIL(S2N_ERR_RSA_PSS_NOT_SUPPORTED);
#endif
}

static bool s2n_evp_md5_sha1_is_supported()
{
#if defined(S2N_LIBCRYPTO_SUPPORTS_EVP_MD5_SHA1_HASH)
    return true;
#else
    return false;
#endif
}

static bool s2n_evp_md_ctx_set_pkey_ctx_is_supported()
{
#ifdef S2N_LIBCRYPTO_SUPPORTS_EVP_MD_CTX_SET_PKEY_CTX
    return true;
#else
    return false;
#endif
}

bool s2n_evp_signing_supported()
{
    /* We must use the FIPS-approved EVP APIs in FIPS mode,
     * but we could also use the EVP APIs outside of FIPS mode.
     * Only using the EVP APIs in FIPS mode was a choice made to reduce
     * the impact of adding support for the EVP APIs.
     * We should consider instead making the EVP APIs the default.
     */
    if (!s2n_is_in_fips_mode()) {
        return false;
    }

    /* Our EVP signing logic is intended to support FIPS 140-3.
     * FIPS 140-3 does not allow externally calculated digests (except for
     * signing, but not verifying, with ECDSA).
     * See https://csrc.nist.gov/Projects/Cryptographic-Algorithm-Validation-Program/Digital-Signatures,
     * and note that "component" tests only exist for ECDSA sign.
     *
     * We currently work around that restriction by calling EVP_MD_CTX_set_pkey_ctx,
     * which lets us set a key on an existing hash state. This is important
     * when we need to handle signing the TLS1.2 client cert verify message,
     * which requires signing the entire message transcript. If EVP_MD_CTX_set_pkey_ctx
     * is unavailable (true for openssl-1.0.2), our current EVP logic will not work.
     *
     * FIPS 140-3 is also not possible if EVP_md5_sha1() isn't available
     * (again true for openssl-1.0.2). In that case, we use two separate hash
     * states to track the md5 and sha1 parts of the hash separately. That means
     * that we also have to calculate the digests separately, then combine the
     * result. We therefore only have an externally calculated digest available
     * for signing or verifying.
     */
    return s2n_evp_md_ctx_set_pkey_ctx_is_supported() && s2n_evp_md5_sha1_is_supported();
}

/* If using EVP signing, override the sign and verify pkey methods.
 * The EVP methods can handle all pkey types / signature algorithms.
 */
S2N_RESULT s2n_evp_signing_set_pkey_overrides(struct s2n_pkey *pkey)
{
    if (s2n_evp_signing_supported()) {
        RESULT_ENSURE_REF(pkey);
        pkey->sign = &s2n_evp_sign;
        pkey->verify = &s2n_evp_verify;
    }
    return S2N_RESULT_OK;
}

static S2N_RESULT s2n_evp_signing_validate_hash_alg(s2n_signature_algorithm sig_alg, s2n_hash_algorithm hash_alg)
{
    switch (hash_alg) {
        case S2N_HASH_NONE:
        case S2N_HASH_MD5:
            /* MD5 alone is never supported */
            RESULT_BAIL(S2N_ERR_HASH_INVALID_ALGORITHM);
            break;
        case S2N_HASH_MD5_SHA1:
            /* Only RSA supports MD5+SHA1.
             * This should not be a problem, as we only allow MD5+SHA1 when
             * falling back to TLS1.0 or 1.1, which only support RSA.
             */
            RESULT_ENSURE(sig_alg == S2N_SIGNATURE_RSA, S2N_ERR_HASH_INVALID_ALGORITHM);
            break;
        default:
            break;
    }
    /* Hash algorithm must be recognized and supported by EVP_MD */
    RESULT_ENSURE(s2n_hash_alg_to_evp_md(hash_alg) != NULL, S2N_ERR_HASH_INVALID_ALGORITHM);
    return S2N_RESULT_OK;
}

static S2N_RESULT s2n_evp_signing_validate_sig_alg(const struct s2n_pkey *key, s2n_signature_algorithm sig_alg)
{
    RESULT_ENSURE_REF(key);

    /* Ensure that the signature algorithm type matches the key type. */
    s2n_pkey_type pkey_type = S2N_PKEY_TYPE_UNKNOWN;
    RESULT_GUARD(s2n_pkey_get_type(key->pkey, &pkey_type));
    s2n_pkey_type sig_alg_type = S2N_PKEY_TYPE_UNKNOWN;
    RESULT_GUARD(s2n_signature_algorithm_get_pkey_type(sig_alg, &sig_alg_type));
    RESULT_ENSURE(pkey_type == sig_alg_type, S2N_ERR_INVALID_SIGNATURE_ALGORITHM);

    return S2N_RESULT_OK;
}

int s2n_evp_sign(const struct s2n_pkey *priv, s2n_signature_algorithm sig_alg,
        struct s2n_hash_state *hash_state, struct s2n_blob *signature)
{
    POSIX_ENSURE_REF(priv);
    POSIX_ENSURE_REF(hash_state);
    POSIX_ENSURE_REF(signature);
    POSIX_ENSURE(s2n_evp_signing_supported(), S2N_ERR_HASH_NOT_READY);
    POSIX_GUARD_RESULT(s2n_evp_signing_validate_hash_alg(sig_alg, hash_state->alg));

    DEFER_CLEANUP(EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new(priv->pkey, NULL), EVP_PKEY_CTX_free_pointer);
    POSIX_ENSURE_REF(pctx);
    POSIX_GUARD_OSSL(EVP_PKEY_sign_init(pctx), S2N_ERR_PKEY_CTX_INIT);
    POSIX_GUARD_OSSL(S2N_EVP_PKEY_CTX_set_signature_md(pctx, s2n_hash_alg_to_evp_md(hash_state->alg)), S2N_ERR_PKEY_CTX_INIT);

    if (sig_alg == S2N_SIGNATURE_RSA_PSS_RSAE || sig_alg == S2N_SIGNATURE_RSA_PSS_PSS) {
        POSIX_GUARD_OSSL(EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING), S2N_ERR_PKEY_CTX_INIT);
        POSIX_GUARD_RESULT(s2n_evp_pkey_set_rsa_pss_saltlen(pctx));
    }

    EVP_MD_CTX *ctx = hash_state->digest.high_level.evp.ctx;
    POSIX_ENSURE_REF(ctx);
    POSIX_GUARD_RESULT(s2n_evp_md_ctx_set_pkey_ctx(ctx, pctx));

    size_t signature_size = signature->size;
    POSIX_GUARD_OSSL(EVP_DigestSignFinal(ctx, signature->data, &signature_size), S2N_ERR_SIGN);
    POSIX_ENSURE(signature_size <= signature->size, S2N_ERR_SIZE_MISMATCH);
    signature->size = signature_size;
    POSIX_GUARD_RESULT(s2n_evp_md_ctx_set_pkey_ctx(ctx, NULL));
    return S2N_SUCCESS;
}

int s2n_evp_verify(const struct s2n_pkey *pub, s2n_signature_algorithm sig_alg,
        struct s2n_hash_state *hash_state, struct s2n_blob *signature)
{
    POSIX_ENSURE_REF(pub);
    POSIX_ENSURE_REF(hash_state);
    POSIX_ENSURE_REF(signature);
    POSIX_ENSURE(s2n_evp_signing_supported(), S2N_ERR_HASH_NOT_READY);
    POSIX_GUARD_RESULT(s2n_evp_signing_validate_hash_alg(sig_alg, hash_state->alg));
    POSIX_GUARD_RESULT(s2n_evp_signing_validate_sig_alg(pub, sig_alg));

    DEFER_CLEANUP(EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new(pub->pkey, NULL), EVP_PKEY_CTX_free_pointer);
    POSIX_ENSURE_REF(pctx);
    POSIX_GUARD_OSSL(EVP_PKEY_verify_init(pctx), S2N_ERR_PKEY_CTX_INIT);
    POSIX_GUARD_OSSL(S2N_EVP_PKEY_CTX_set_signature_md(pctx, s2n_hash_alg_to_evp_md(hash_state->alg)), S2N_ERR_PKEY_CTX_INIT);

    if (sig_alg == S2N_SIGNATURE_RSA_PSS_RSAE || sig_alg == S2N_SIGNATURE_RSA_PSS_PSS) {
        POSIX_GUARD_OSSL(EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING), S2N_ERR_PKEY_CTX_INIT);
        POSIX_GUARD_RESULT(s2n_evp_pkey_set_rsa_pss_saltlen(pctx));
    }

    EVP_MD_CTX *ctx = hash_state->digest.high_level.evp.ctx;
    POSIX_ENSURE_REF(ctx);
    POSIX_GUARD_RESULT(s2n_evp_md_ctx_set_pkey_ctx(ctx, pctx));

    POSIX_GUARD_OSSL(EVP_DigestVerifyFinal(ctx, signature->data, signature->size), S2N_ERR_VERIFY_SIGNATURE);
    POSIX_GUARD_RESULT(s2n_evp_md_ctx_set_pkey_ctx(ctx, NULL));
    return S2N_SUCCESS;
}
