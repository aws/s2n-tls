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
#include <stdint.h>

#include "error/s2n_errno.h"

#include "stuffer/s2n_stuffer.h"

#include "crypto/s2n_hash.h"
#include "crypto/s2n_openssl.h"
#include "crypto/s2n_rsa.h"
#include "crypto/s2n_rsa_pss.h"
#include "crypto/s2n_rsa_signing.h"
#include "crypto/s2n_pkey.h"

#include "utils/s2n_blob.h"
#include "utils/s2n_random.h"
#include "utils/s2n_safety.h"
#include "utils/s2n_blob.h"

/* Checks whether PSS Certs is supported */
int s2n_is_rsa_pss_certs_supported()
{
    return RSA_PSS_CERTS_SUPPORTED;
}

#if RSA_PSS_CERTS_SUPPORTED

static int s2n_rsa_pss_size(const struct s2n_pkey *key)
{
    notnull_check(key);

    /* For more info, see: https://www.openssl.org/docs/man1.1.0/man3/EVP_PKEY_size.html */
    return EVP_PKEY_size(key->pkey);
}

static int s2n_rsa_is_private_key(RSA *rsa_key)
{
    const BIGNUM *d = NULL;
    RSA_get0_key(rsa_key, NULL, NULL, &d);

    if (d != NULL) {
        return 1;
    }
    return 0;
}

int s2n_rsa_pss_key_sign(const struct s2n_pkey *priv, s2n_signature_algorithm sig_alg,
        struct s2n_hash_state *digest, struct s2n_blob *signature_out)
{
    notnull_check(priv);
    sig_alg_check(sig_alg, S2N_SIGNATURE_RSA_PSS_PSS);

    /* Not Possible to Sign with Public Key */
    S2N_ERROR_IF(!s2n_rsa_is_private_key(priv->key.rsa_key.rsa), S2N_ERR_KEY_MISMATCH);

    return s2n_rsa_pss_sign(priv, digest, signature_out);
}

int s2n_rsa_pss_key_verify(const struct s2n_pkey *pub, s2n_signature_algorithm sig_alg,
        struct s2n_hash_state *digest, struct s2n_blob *signature_in)
{
    notnull_check(pub);
    sig_alg_check(sig_alg, S2N_SIGNATURE_RSA_PSS_PSS);

    /* Using Private Key to Verify means the public/private keys were likely swapped, and likely indicates a bug. */
    S2N_ERROR_IF(s2n_rsa_is_private_key(pub->key.rsa_key.rsa), S2N_ERR_KEY_MISMATCH);

    return s2n_rsa_pss_verify(pub, digest, signature_in);
}

static int s2n_rsa_pss_validate_sign_verify_match(const struct s2n_pkey *pub, const struct s2n_pkey *priv)
{
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
    GUARD(s2n_rsa_pss_key_sign(priv, S2N_SIGNATURE_RSA_PSS_PSS, &sign_hash, &signature_data));
    GUARD(s2n_rsa_pss_key_verify(pub, S2N_SIGNATURE_RSA_PSS_PSS, &verify_hash, &signature_data));

    return 0;
}

static int s2n_rsa_validate_params_equal(const RSA *pub, const RSA *priv)
{
    const BIGNUM *pub_val_e = NULL;
    const BIGNUM *pub_val_n = NULL;
    RSA_get0_key(pub, &pub_val_n, &pub_val_e, NULL);

    const BIGNUM *priv_val_e = NULL;
    const BIGNUM *priv_val_n = NULL;
    RSA_get0_key(priv, &priv_val_n, &priv_val_e, NULL);

    if (pub_val_e == NULL || priv_val_e == NULL) {
        S2N_ERROR(S2N_ERR_KEY_CHECK);
    }

    if (pub_val_n == NULL || priv_val_n == NULL) {
        S2N_ERROR(S2N_ERR_KEY_CHECK);
    }

    S2N_ERROR_IF(BN_cmp(pub_val_e, priv_val_e) != 0, S2N_ERR_KEY_MISMATCH);
    S2N_ERROR_IF(BN_cmp(pub_val_n, priv_val_n) != 0, S2N_ERR_KEY_MISMATCH);

    return 0;
}

static int s2n_rsa_validate_params_match(const struct s2n_pkey *pub, const struct s2n_pkey *priv)
{
    notnull_check(pub);
    notnull_check(priv);

    /* OpenSSL Documentation Links:
     *  - https://www.openssl.org/docs/manmaster/man3/EVP_PKEY_get0_RSA.html
     *  - https://www.openssl.org/docs/manmaster/man3/RSA_get0_key.html
     */
    RSA *pub_rsa_key = pub->key.rsa_key.rsa;
    RSA *priv_rsa_key = priv->key.rsa_key.rsa;

    notnull_check(pub_rsa_key);
    notnull_check(priv_rsa_key);

    GUARD(s2n_rsa_validate_params_equal(pub_rsa_key, priv_rsa_key));

    return 0;
}


static int s2n_rsa_pss_keys_match(const struct s2n_pkey *pub, const struct s2n_pkey *priv)
{
    notnull_check(pub);
    notnull_check(pub->pkey);
    notnull_check(priv);
    notnull_check(priv->pkey);

    GUARD(s2n_rsa_validate_params_match(pub, priv));

    /* Validate that verify(sign(message)) for a random message is verified correctly */
    GUARD(s2n_rsa_pss_validate_sign_verify_match(pub, priv));

    return 0;
}

static int s2n_rsa_pss_key_free(struct s2n_pkey *pkey)
{
    /* This object does not own the reference to the key --
     * s2n_pkey handles it. */

    return 0;
}

int s2n_evp_pkey_to_rsa_pss_public_key(struct s2n_rsa_key *rsa_key, EVP_PKEY *pkey) {
    RSA *pub_rsa_key = EVP_PKEY_get0_RSA(pkey);

    S2N_ERROR_IF(s2n_rsa_is_private_key(pub_rsa_key), S2N_ERR_KEY_MISMATCH);

    rsa_key->rsa = pub_rsa_key;
    return 0;
}

int s2n_evp_pkey_to_rsa_pss_private_key(struct s2n_rsa_key *rsa_key, EVP_PKEY *pkey)
{
    RSA *priv_rsa_key = EVP_PKEY_get0_RSA(pkey);
    notnull_check(priv_rsa_key);

    /* Documentation: https://www.openssl.org/docs/man1.1.1/man3/RSA_check_key.html */
    S2N_ERROR_IF(!s2n_rsa_is_private_key(priv_rsa_key), S2N_ERR_KEY_MISMATCH);

    /* Check that the mandatory properties of a RSA Private Key are valid.
     *  - Documentation: https://www.openssl.org/docs/man1.1.1/man3/RSA_check_key.html
     */
    GUARD_OSSL(RSA_check_key(priv_rsa_key), S2N_ERR_KEY_CHECK);

    rsa_key->rsa = priv_rsa_key;
    return 0;
}

int s2n_rsa_pss_pkey_init(struct s2n_pkey *pkey)
{
    GUARD(s2n_rsa_pkey_init(pkey));

    pkey->size = &s2n_rsa_pss_size;
    pkey->sign = &s2n_rsa_pss_key_sign;
    pkey->verify = &s2n_rsa_pss_key_verify;

    /* RSA PSS only supports Sign and Verify.
     * RSA PSS should never be used for Key Exchange. ECDHE should be used instead since it provides Forward Secrecy. */
    pkey->encrypt = NULL; /* No function for encryption */
    pkey->decrypt = NULL; /* No function for decryption */

    pkey->match = &s2n_rsa_pss_keys_match;
    pkey->free = &s2n_rsa_pss_key_free;

    return 0;
}

#else

int s2n_evp_pkey_to_rsa_pss_public_key(struct s2n_rsa_key *rsa_pss_key, EVP_PKEY *pkey)
{
    S2N_ERROR(S2N_RSA_PSS_NOT_SUPPORTED);
}

int s2n_evp_pkey_to_rsa_pss_private_key(struct s2n_rsa_key *rsa_pss_key, EVP_PKEY *pkey)
{
    S2N_ERROR(S2N_RSA_PSS_NOT_SUPPORTED);
}

int s2n_rsa_pss_pkey_init(struct s2n_pkey *pkey)
{
    S2N_ERROR(S2N_RSA_PSS_NOT_SUPPORTED);
}

#endif
