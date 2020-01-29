/*
 * Copyright 2017 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/x509.h>
#include "stuffer/s2n_stuffer.h"

#include "error/s2n_errno.h"
#include "utils/s2n_blob.h"
#include "utils/s2n_mem.h"
#include "utils/s2n_random.h"
#include "utils/s2n_safety.h"

#include "crypto/s2n_ecdsa.h"
#include "crypto/s2n_hash.h"
#include "crypto/s2n_openssl.h"
#include "crypto/s2n_pkey.h"

int s2n_ecdsa_der_signature_size(const struct s2n_pkey *pkey)
{
    const struct s2n_ecdsa_key *ecdsa_key = &pkey->key.ecdsa_key;
    notnull_check(ecdsa_key->ec_key);

    return ECDSA_size(ecdsa_key->ec_key);
}

static int s2n_ecdsa_sign(const struct s2n_pkey *priv, struct s2n_hash_state *digest, struct s2n_blob *signature)
{
    const s2n_ecdsa_private_key *key = &priv->key.ecdsa_key;
    notnull_check(key->ec_key);

    uint8_t digest_length;
    GUARD(s2n_hash_digest_size(digest->alg, &digest_length));
    lte_check(digest_length, S2N_MAX_DIGEST_LEN);

    uint8_t digest_out[S2N_MAX_DIGEST_LEN];
    GUARD(s2n_hash_digest(digest, digest_out, digest_length));

    unsigned int signature_size = signature->size;
    GUARD_OSSL(ECDSA_sign(0, digest_out, digest_length, signature->data, &signature_size, key->ec_key), S2N_ERR_SIGN);
    S2N_ERROR_IF(signature_size > signature->size, S2N_ERR_SIZE_MISMATCH);
    signature->size = signature_size;

    GUARD(s2n_hash_reset(digest));
    
    return 0;
}

static int s2n_ecdsa_verify(const struct s2n_pkey *pub, struct s2n_hash_state *digest, struct s2n_blob *signature)
{
    const s2n_ecdsa_public_key *key = &pub->key.ecdsa_key;
    notnull_check(key->ec_key);

    uint8_t digest_length;
    GUARD(s2n_hash_digest_size(digest->alg, &digest_length));
    lte_check(digest_length, S2N_MAX_DIGEST_LEN);

    uint8_t digest_out[S2N_MAX_DIGEST_LEN];
    GUARD(s2n_hash_digest(digest, digest_out, digest_length));
    
    /* ECDSA_verify ignores the first parameter */
    GUARD_OSSL(ECDSA_verify(0, digest_out, digest_length, signature->data, signature->size, key->ec_key), S2N_ERR_VERIFY_SIGNATURE);

    GUARD(s2n_hash_reset(digest));
    
    return 0;
}

static int s2n_ecdsa_keys_match(const struct s2n_pkey *pub, const struct s2n_pkey *priv) 
{
    uint8_t input[16] = { 1 };
    DEFER_CLEANUP(struct s2n_blob signature = { 0 }, s2n_free);
    DEFER_CLEANUP(struct s2n_hash_state state_in = { 0 }, s2n_hash_free);
    DEFER_CLEANUP(struct s2n_hash_state state_out = { 0 }, s2n_hash_free);

    /* s2n_hash_new only allocates memory when using high-level EVP hashes, currently restricted to FIPS mode. */
    GUARD(s2n_hash_new(&state_in));
    GUARD(s2n_hash_new(&state_out));

    GUARD(s2n_hash_init(&state_in, S2N_HASH_SHA1));
    GUARD(s2n_hash_init(&state_out, S2N_HASH_SHA1));
    GUARD(s2n_hash_update(&state_in, input, sizeof(input)));
    GUARD(s2n_hash_update(&state_out, input, sizeof(input)));

    GUARD(s2n_alloc(&signature, s2n_ecdsa_der_signature_size(priv)));

    GUARD(s2n_ecdsa_sign(priv, &state_in, &signature));
    GUARD(s2n_ecdsa_verify(pub, &state_out, &signature));

    return 0;
}

static int s2n_ecdsa_key_free(struct s2n_pkey *pkey)
{
    struct s2n_ecdsa_key *ecdsa_key = &pkey->key.ecdsa_key;
    if (ecdsa_key->ec_key == NULL) {
        return 0;
    }
    
    EC_KEY_free(ecdsa_key->ec_key);
    ecdsa_key->ec_key = NULL;

    return 0;
}

static int s2n_ecdsa_check_key_exists(const struct s2n_pkey *pkey)
{
    const struct s2n_ecdsa_key *ecdsa_key = &pkey->key.ecdsa_key;
    notnull_check(ecdsa_key->ec_key);
    return 0;
}

int s2n_evp_pkey_to_ecdsa_private_key(s2n_ecdsa_private_key *ecdsa_key, EVP_PKEY *evp_private_key)
{
    EC_KEY *ec_key = EVP_PKEY_get1_EC_KEY(evp_private_key);
    S2N_ERROR_IF(ec_key == NULL, S2N_ERR_DECODE_PRIVATE_KEY);
    
    ecdsa_key->ec_key = ec_key;
    return 0;
}

int s2n_evp_pkey_to_ecdsa_public_key(s2n_ecdsa_public_key *ecdsa_key, EVP_PKEY *evp_public_key)
{
    EC_KEY *ec_key = EVP_PKEY_get1_EC_KEY(evp_public_key);
    S2N_ERROR_IF(ec_key == NULL, S2N_ERR_DECODE_CERTIFICATE);
    
    ecdsa_key->ec_key = ec_key;
    return 0;
}

int s2n_ecdsa_pkey_init(struct s2n_pkey *pkey) {
    pkey->size = &s2n_ecdsa_der_signature_size;
    pkey->sign = &s2n_ecdsa_sign;
    pkey->verify = &s2n_ecdsa_verify;
    pkey->encrypt = NULL; /* No function for encryption */
    pkey->decrypt = NULL; /* No function for decryption */
    pkey->match = &s2n_ecdsa_keys_match;
    pkey->free = &s2n_ecdsa_key_free;
    pkey->check_key = &s2n_ecdsa_check_key_exists;
    return 0;
}
