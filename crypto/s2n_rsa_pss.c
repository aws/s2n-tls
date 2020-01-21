/*
 * Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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
#include <stdint.h>

#include "error/s2n_errno.h"

#include "stuffer/s2n_stuffer.h"

#include "crypto/s2n_hash.h"
#include "crypto/s2n_openssl.h"
#include "crypto/s2n_rsa.h"
#include "crypto/s2n_rsa_pss.h"
#include "crypto/s2n_pkey.h"

#include "utils/s2n_blob.h"
#include "utils/s2n_random.h"
#include "utils/s2n_safety.h"
#include "utils/s2n_blob.h"

#if RSA_PSS_SUPPORTED

#define S2N_PARAM_NOT_REQUIRED  0
#define S2N_PARAM_REQUIRED      1

typedef const BIGNUM *(*ossl_get_rsa_param_fn) (const RSA *d);

const EVP_MD* s2n_hash_alg_to_evp_alg(s2n_hash_algorithm alg) {
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

static int s2n_rsa_pss_size(const struct s2n_pkey *key)
{
    notnull_check(key);

    /* For more info, see: https://www.openssl.org/docs/man1.1.0/man3/EVP_PKEY_size.html */
    return EVP_PKEY_size(key->key.rsa_pss_key.pkey);
}


static int s2n_rsa_is_private_key(EVP_PKEY *pkey) {

    RSA *rsa_key = EVP_PKEY_get0_RSA(pkey);

    const BIGNUM *d = RSA_get0_d(rsa_key);
    const BIGNUM *p = RSA_get0_p(rsa_key);
    const BIGNUM *q = RSA_get0_q(rsa_key);

    if (d || p || q) {
        return 1;
    }

    return 0;
}

static void s2n_evp_pkey_ctx_free(EVP_PKEY_CTX **ctx) {

    if (ctx != NULL) {
        EVP_PKEY_CTX_free(*ctx);
    }
}

/* On some versions of OpenSSL, "EVP_PKEY_CTX_set_signature_md()" is just a macro that casts digest_alg to "void*",
 * which fails to compile when the "-Werror=cast-qual" compiler flag is enabled. So we work around this OpenSSL
 * issue by turning off this compiler check for this one function. */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-qual"
static int s2n_evp_pkey_ctx_set_rsa_signature_digest(EVP_PKEY_CTX *ctx, const EVP_MD* digest_alg) {
    GUARD_OSSL(EVP_PKEY_CTX_set_signature_md(ctx, digest_alg), S2N_ERR_INVALID_SIGNATURE_ALGORITHM);
    GUARD_OSSL(EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, digest_alg), S2N_ERR_INVALID_SIGNATURE_ALGORITHM);
    return 0;
}
#pragma GCC diagnostic pop

int s2n_rsa_pss_sign(const struct s2n_pkey *priv, struct s2n_hash_state *digest, struct s2n_blob *signature_out)
{
    notnull_check(priv);

    /* Not Possible to Sign with Public Key */
    S2N_ERROR_IF(!s2n_rsa_is_private_key(priv->key.rsa_pss_key.pkey), S2N_ERR_KEY_MISMATCH);

    uint8_t digest_length;
    uint8_t digest_data[S2N_MAX_DIGEST_LEN];
    GUARD(s2n_hash_digest_size(digest->alg, &digest_length));
    GUARD(s2n_hash_digest(digest, digest_data, digest_length));

    const EVP_MD* digest_alg = s2n_hash_alg_to_evp_alg(digest->alg);
    notnull_check(digest_alg);

    /* For more info see: https://www.openssl.org/docs/manmaster/man3/EVP_PKEY_sign.html */
    DEFER_CLEANUP(EVP_PKEY_CTX *ctx  = EVP_PKEY_CTX_new(priv->key.rsa_pss_key.pkey, NULL), s2n_evp_pkey_ctx_free);
    notnull_check(ctx);

    size_t signature_len = signature_out->size;
    GUARD_OSSL(EVP_PKEY_sign_init(ctx), S2N_ERR_SIGN);
    GUARD_OSSL(EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PSS_PADDING), S2N_ERR_SIGN);
    GUARD(s2n_evp_pkey_ctx_set_rsa_signature_digest(ctx, digest_alg));
    GUARD_OSSL(EVP_PKEY_CTX_set_rsa_pss_saltlen(ctx, RSA_PSS_SALTLEN_DIGEST), S2N_ERR_SIGN);

    /* Calling EVP_PKEY_sign() with NULL will only update the signature_len parameter so users can validate sizes. */
    GUARD_OSSL(EVP_PKEY_sign(ctx, NULL, &signature_len, digest_data, digest_length), S2N_ERR_SIGN);
    S2N_ERROR_IF(signature_len > signature_out->size, S2N_ERR_SIZE_MISMATCH);

    /* Actually sign the the digest */
    GUARD_OSSL(EVP_PKEY_sign(ctx, signature_out->data, &signature_len, digest_data, digest_length), S2N_ERR_SIGN);
    signature_out->size = signature_len;

    return 0;
}

int s2n_rsa_pss_verify(const struct s2n_pkey *pub, struct s2n_hash_state *digest, struct s2n_blob *signature_in)
{
    notnull_check(pub);

    /* Using Private Key to Verify means the public/private keys were likely swapped, and likely indicates a bug. */
    S2N_ERROR_IF(s2n_rsa_is_private_key(pub->key.rsa_pss_key.pkey), S2N_ERR_KEY_MISMATCH);

    uint8_t digest_length;
    uint8_t digest_data[S2N_MAX_DIGEST_LEN];
    GUARD(s2n_hash_digest_size(digest->alg, &digest_length));
    GUARD(s2n_hash_digest(digest, digest_data, digest_length));
    const EVP_MD* digest_alg = s2n_hash_alg_to_evp_alg(digest->alg);
    notnull_check(digest_alg);

    /* For more info see: https://www.openssl.org/docs/manmaster/man3/EVP_PKEY_verify.html */
    DEFER_CLEANUP(EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pub->key.rsa_pss_key.pkey, NULL), s2n_evp_pkey_ctx_free);
    notnull_check(ctx);

    GUARD_OSSL(EVP_PKEY_verify_init(ctx), S2N_ERR_VERIFY_SIGNATURE);
    GUARD_OSSL(EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PSS_PADDING), S2N_ERR_SIGN);
    GUARD(s2n_evp_pkey_ctx_set_rsa_signature_digest(ctx, digest_alg));
    GUARD_OSSL(EVP_PKEY_verify(ctx, signature_in->data, signature_in->size, digest_data, digest_length), S2N_ERR_VERIFY_SIGNATURE);

    return 0;
}

static int s2n_rsa_pss_validate_sign_verify_match(const struct s2n_pkey *pub, const struct s2n_pkey *priv) {
    /* Generate a random blob to sign and verify */
    s2n_stack_blob(random_data, RSA_PSS_SIGN_VERIFY_RANDOM_BLOB_SIZE, RSA_PSS_SIGN_VERIFY_RANDOM_BLOB_SIZE);
    GUARD(s2n_get_private_random_data(&random_data));

    /* Sign/Verify API's only accept Hashes, so hash our Random Data */
    DEFER_CLEANUP(struct s2n_hash_state sign_hash = {0}, s2n_hash_free);
    DEFER_CLEANUP(struct s2n_hash_state verify_hash = {0}, s2n_hash_free);
    GUARD(s2n_hash_new(&sign_hash));
    GUARD(s2n_hash_new(&verify_hash));
    GUARD(s2n_hash_init(&sign_hash, S2N_HASH_SHA256));
    GUARD(s2n_hash_init(&verify_hash, S2N_HASH_SHA256));
    GUARD(s2n_hash_update(&sign_hash, random_data.data, random_data.size));
    GUARD(s2n_hash_update(&verify_hash, random_data.data, random_data.size));

    /* Sign and Verify the Hash of the Random Blob */
    s2n_stack_blob(signature_data, RSA_PSS_SIGN_VERIFY_SIGNATURE_SIZE, RSA_PSS_SIGN_VERIFY_SIGNATURE_SIZE);
    GUARD(s2n_rsa_pss_sign(priv, &sign_hash, &signature_data));
    GUARD(s2n_rsa_pss_verify(pub, &verify_hash, &signature_data));

    return 0;
}

static int s2n_rsa_validate_param_equal(const RSA *pub, const RSA *priv, int required,
                                        ossl_get_rsa_param_fn get_rsa_param_fn) {

    const BIGNUM *pub_val = get_rsa_param_fn(pub);
    const BIGNUM *priv_val = get_rsa_param_fn(priv);

    if (required && (pub_val == NULL || priv_val == NULL)) {
        S2N_ERROR(S2N_ERR_KEY_CHECK);
    }

    if (pub_val != NULL && priv_val != NULL) {
        S2N_ERROR_IF(BN_cmp(pub_val, priv_val) != 0, S2N_ERR_KEY_MISMATCH);
    }

    return 0;
}

static int s2n_rsa_validate_params_match(const struct s2n_pkey *pub, const struct s2n_pkey *priv) {
    notnull_check(pub);
    notnull_check(priv);

    /* OpenSSL Documentation Links:
     *  - https://www.openssl.org/docs/manmaster/man3/EVP_PKEY_get0_RSA.html
     *  - https://www.openssl.org/docs/manmaster/man3/RSA_get0_n.html
     */
    RSA *pub_rsa_key = EVP_PKEY_get0_RSA(pub->key.rsa_pss_key.pkey);
    RSA *priv_rsa_key = EVP_PKEY_get0_RSA(priv->key.rsa_pss_key.pkey);

    notnull_check(pub_rsa_key);
    notnull_check(priv_rsa_key);

    GUARD(s2n_rsa_validate_param_equal(pub_rsa_key, priv_rsa_key, S2N_PARAM_REQUIRED, &RSA_get0_n));
    GUARD(s2n_rsa_validate_param_equal(pub_rsa_key, priv_rsa_key, S2N_PARAM_NOT_REQUIRED, &RSA_get0_e));

    return 0;
}


static int s2n_rsa_pss_keys_match(const struct s2n_pkey *pub, const struct s2n_pkey *priv)
{
    notnull_check(pub);
    notnull_check(pub->key.rsa_pss_key.pkey);
    notnull_check(priv);
    notnull_check(priv->key.rsa_pss_key.pkey);

    GUARD(s2n_rsa_validate_params_match(pub, priv));

    /* Validate that verify(sign(message)) for a random message is verified correctly */
    GUARD(s2n_rsa_pss_validate_sign_verify_match(pub, priv));

    return 0;
}

static int s2n_rsa_pss_key_free(struct s2n_pkey *pkey)
{
    struct s2n_rsa_pss_key key = pkey->key.rsa_pss_key;

    if (key.pkey != NULL) {
        EVP_PKEY_free(key.pkey);
        key.pkey = NULL;
    }

    return 0;
}

static int s2n_rsa_pss_check_key_exists(const struct s2n_pkey *pkey)
{
    const struct s2n_rsa_pss_key key = pkey->key.rsa_pss_key;
    notnull_check(key.pkey);
    return 0;
}

int s2n_evp_pkey_to_rsa_pss_public_key(struct s2n_rsa_pss_key *rsa_pss_key, EVP_PKEY *pkey) {
    S2N_ERROR_IF(s2n_rsa_is_private_key(pkey), S2N_ERR_KEY_MISMATCH);
    GUARD_OSSL(EVP_PKEY_up_ref(pkey), S2N_ERR_KEY_INIT);

    rsa_pss_key->pkey = pkey;
    return 0;
}

int s2n_evp_pkey_to_rsa_pss_private_key(struct s2n_rsa_pss_key *rsa_pss_key, EVP_PKEY *pkey) {
    RSA *priv_rsa_key = EVP_PKEY_get0_RSA(pkey);
    notnull_check(priv_rsa_key);

    /* Documentation: https://www.openssl.org/docs/man1.1.1/man3/RSA_check_key.html */
    S2N_ERROR_IF(!s2n_rsa_is_private_key(pkey), S2N_ERR_KEY_MISMATCH);

    /* Check that the mandatory properties of a RSA Private Key are valid.
     *  - Documentation: https://www.openssl.org/docs/man1.1.1/man3/RSA_check_key.html
     */
    GUARD_OSSL(RSA_check_key(priv_rsa_key), S2N_ERR_KEY_CHECK);
    GUARD_OSSL(EVP_PKEY_up_ref(pkey), S2N_ERR_KEY_INIT);

    rsa_pss_key->pkey = pkey;
    return 0;
}

int s2n_rsa_pss_pkey_init(struct s2n_pkey *pkey)
{
    pkey->size = &s2n_rsa_pss_size;
    pkey->sign = &s2n_rsa_pss_sign;
    pkey->verify = &s2n_rsa_pss_verify;

    /* RSA PSS only supports Sign and Verify.
     * RSA PSS should never be used for Key Exchange. ECDHE should be used instead since it provides Forward Secrecy. */
    pkey->encrypt = NULL; /* No function for encryption */
    pkey->decrypt = NULL; /* No function for decryption */

    pkey->match = &s2n_rsa_pss_keys_match;
    pkey->free = &s2n_rsa_pss_key_free;
    pkey->check_key = &s2n_rsa_pss_check_key_exists;

    return 0;
}

#endif
