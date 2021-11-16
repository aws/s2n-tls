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

#include "error/s2n_errno.h"

#include "crypto/s2n_evp.h"
#include "crypto/s2n_pkey.h"

#include "utils/s2n_blob.h"
#include "utils/s2n_safety.h"

/*
 * FIPS 140-3 requires that we don't pass raw digest bytes to the libcrypto signing methods.
 * In order to do that, we need to use signing methods that both calculate the digest and
 * perform the signature.
 */

/* Currently, EVP_MD_CTX_set_pkey_ctx is only available in OpenSSL.
 * AwsLC will need to add it in order to use this method of signing.
 */
static S2N_RESULT s2n_evp_md_ctx_set_pkey_ctx(EVP_MD_CTX *ctx, EVP_PKEY_CTX *pctx)
{
#if S2N_OPENSSL_VERSION_AT_LEAST(1,1,1)
    EVP_MD_CTX_set_pkey_ctx(ctx, pctx);
    return S2N_RESULT_OK;
#else
    RESULT_BAIL(S2N_ERR_UNIMPLEMENTED);
#endif
}

S2N_RESULT s2n_evp_sign(const struct s2n_pkey *priv, s2n_signature_algorithm sig_alg,
        struct s2n_hash_state *hash_state, struct s2n_blob *signature)
{
    RESULT_ENSURE_REF(priv);
    RESULT_ENSURE_REF(hash_state);
    RESULT_ENSURE_REF(signature);

    /* We can only use this signing method if the hash state has an EVP_MD_CTX
     * that we can pass to the EVP signing methods.
     */
    RESULT_ENSURE(s2n_hash_evp_fully_supported(), S2N_ERR_HASH_NOT_READY);

    switch(hash_state->alg) {
        case S2N_HASH_NONE:
            /* No hash algorithm set when we calculate a digest + signature
             * doesn't make much sense, but we treat it as a no-op instead
             * of an error to match the behavior of s2n-tls's other signing
             * methods.
             */
            return S2N_RESULT_OK;
        case S2N_HASH_MD5:
        case S2N_HASH_MD5_SHA1:
            /* ECDSA does not support MD5.
             * This should not be a problem, as we only allow MD5 when
             * falling back to TLS1.0 or 1.1, which do not support ECDSA.
             * No signature scheme supports ECDSA + MD5.
             */
            RESULT_ENSURE(sig_alg != S2N_SIGNATURE_ECDSA, S2N_ERR_HASH_INVALID_ALGORITHM);
            break;
        default:
            break;
    }

    EVP_MD_CTX *ctx = hash_state->digest.high_level.evp.ctx;
    RESULT_ENSURE_REF(ctx);

    EVP_PKEY_CTX *pctx  = EVP_PKEY_CTX_new(priv->pkey, NULL);
    RESULT_ENSURE_REF(pctx);
    RESULT_GUARD(s2n_evp_md_ctx_set_pkey_ctx(ctx, pctx));

    RESULT_GUARD_OSSL(EVP_PKEY_sign_init(pctx), S2N_ERR_PKEY_CTX_INIT);
    RESULT_ENSURE_REF(s2n_hash_alg_to_evp_md(hash_state->alg));
    RESULT_GUARD_OSSL(S2N_EVP_PKEY_CTX_set_signature_md(pctx, s2n_hash_alg_to_evp_md(hash_state->alg)), S2N_ERR_PKEY_CTX_INIT);
    if (sig_alg == S2N_SIGNATURE_RSA_PSS_RSAE) {
        RESULT_GUARD_OSSL(EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING), S2N_ERR_PKEY_CTX_INIT);
        RESULT_GUARD_OSSL(EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, RSA_PSS_SALTLEN_DIGEST), S2N_ERR_PKEY_CTX_INIT);
    }

    size_t signature_size = signature->size;
    RESULT_GUARD_OSSL(EVP_DigestSignFinal(ctx, signature->data, &signature_size), S2N_ERR_SIGN);
    RESULT_ENSURE(signature_size <= signature->size, S2N_ERR_SIZE_MISMATCH);
    signature->size = signature_size;
    return S2N_RESULT_OK;
}

S2N_RESULT s2n_evp_verify(const struct s2n_pkey *pub, s2n_signature_algorithm sig_alg,
        struct s2n_hash_state *hash_state, struct s2n_blob *signature)
{
    RESULT_ENSURE_REF(pub);
    RESULT_ENSURE_REF(hash_state);
    RESULT_ENSURE_REF(signature);

    /* We can only use this verify method if the hash state has an EVP_MD_CTX
     * that we can pass to the EVP verify methods.
     */
    RESULT_ENSURE(s2n_hash_evp_fully_supported(), S2N_ERR_HASH_NOT_READY);

    switch(hash_state->alg) {
        case S2N_HASH_NONE:
            /* No hash algorithm set when we calculate a digest + signature
             * doesn't make much sense, but we treat it as a no-op instead
             * of an error to match the behavior of s2n-tls's other signing
             * methods.
             */
            return S2N_RESULT_OK;
        case S2N_HASH_MD5:
        case S2N_HASH_MD5_SHA1:
            /* ECDSA does not support MD5.
             * This should not be a problem, as we only allow MD5 when
             * falling back to TLS1.0 or 1.1, which do not support ECDSA.
             * No signature scheme supports ECDSA + MD5.
             */
            RESULT_ENSURE(sig_alg != S2N_SIGNATURE_ECDSA, S2N_ERR_HASH_INVALID_ALGORITHM);
            break;
        default:
            break;
    }

    EVP_MD_CTX *ctx = hash_state->digest.high_level.evp.ctx;
    RESULT_ENSURE_REF(ctx);

    EVP_PKEY_CTX *pctx  = EVP_PKEY_CTX_new(pub->pkey, NULL);
    RESULT_ENSURE_REF(pctx);
    RESULT_GUARD(s2n_evp_md_ctx_set_pkey_ctx(ctx, pctx));

    RESULT_GUARD_OSSL(EVP_PKEY_verify_init(pctx), S2N_ERR_PKEY_CTX_INIT);
    RESULT_ENSURE_REF(s2n_hash_alg_to_evp_md(hash_state->alg));
    RESULT_GUARD_OSSL(S2N_EVP_PKEY_CTX_set_signature_md(pctx, s2n_hash_alg_to_evp_md(hash_state->alg)), S2N_ERR_PKEY_CTX_INIT);
    if (sig_alg == S2N_SIGNATURE_RSA_PSS_RSAE) {
        RESULT_GUARD_OSSL(EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING), S2N_ERR_PKEY_CTX_INIT);
    }

    RESULT_GUARD_OSSL(EVP_DigestVerifyFinal(ctx, signature->data, signature->size), S2N_ERR_VERIFY_SIGNATURE);
    return S2N_RESULT_OK;
}
