/*
 * Copyright 2014 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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
#include "crypto/s2n_pkey.h"

#include "utils/s2n_blob.h"
#include "utils/s2n_random.h"
#include "utils/s2n_safety.h"
#include "utils/s2n_blob.h"

static int s2n_rsa_modulus_check(RSA *rsa)
{
    /* RSA was made opaque starting in Openssl 1.1.0 */
    #if S2N_OPENSSL_VERSION_AT_LEAST(1,1,0) && !defined(LIBRESSL_VERSION_NUMBER)
        const BIGNUM *n = NULL;
        /* RSA still owns the memory for n */
        RSA_get0_key(rsa, &n, NULL, NULL);
        notnull_check(n);
    #else
        notnull_check(rsa->n);
    #endif
    return 0;
}

static int s2n_rsa_encrypted_size(const struct s2n_rsa_key *key)
{
    notnull_check(key->rsa);
    GUARD(s2n_rsa_modulus_check(key->rsa));

    return RSA_size(key->rsa);
}

int s2n_rsa_public_encrypted_size(const s2n_rsa_public_key *key)
{
    return s2n_rsa_encrypted_size(key);
}

int s2n_rsa_private_encrypted_size(const s2n_rsa_private_key *key)
{
    return s2n_rsa_encrypted_size(key);
}

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
        S2N_ERROR(S2N_ERR_HASH_INVALID_ALGORITHM);
    }
    return 0;
}

static int s2n_rsa_sign(const struct s2n_pkey *priv, struct s2n_hash_state *digest, struct s2n_blob *signature)
{
    uint8_t digest_length;
    int NID_type;
    GUARD(s2n_hash_digest_size(digest->alg, &digest_length));
    GUARD(s2n_hash_NID_type(digest->alg, &NID_type));
    lte_check(digest_length, S2N_MAX_DIGEST_LEN);

    const s2n_rsa_private_key *key = &priv->key.rsa_key;

    uint8_t digest_out[S2N_MAX_DIGEST_LEN];
    GUARD(s2n_hash_digest(digest, digest_out, digest_length));

    unsigned int signature_size = signature->size;
    if (RSA_sign(NID_type, digest_out, digest_length, signature->data, &signature_size, key->rsa) == 0) {
        S2N_ERROR(S2N_ERR_SIGN);
    }
    if (signature_size > signature->size) {
        S2N_ERROR(S2N_ERR_SIZE_MISMATCH);
    }
    signature->size = signature_size;

    return 0;
}

static int s2n_rsa_verify(const struct s2n_pkey *pub, struct s2n_hash_state *digest, struct s2n_blob *signature)
{
    uint8_t digest_length;
    int NID_type;
    GUARD(s2n_hash_digest_size(digest->alg, &digest_length));
    GUARD(s2n_hash_NID_type(digest->alg, &NID_type));
    lte_check(digest_length, S2N_MAX_DIGEST_LEN);

    const s2n_rsa_public_key *key = &pub->key.rsa_key;

    uint8_t digest_out[S2N_MAX_DIGEST_LEN];
    GUARD(s2n_hash_digest(digest, digest_out, digest_length));

    if (RSA_verify(NID_type, digest_out, digest_length, signature->data, signature->size, key->rsa) == 0) {
        S2N_ERROR(S2N_ERR_VERIFY_SIGNATURE);
    }

    return 0;
}

static int s2n_rsa_encrypt(const struct s2n_pkey *pub, struct s2n_blob *in, struct s2n_blob *out)
{
    const s2n_rsa_public_key *key = &pub->key.rsa_key;
    
    if (out->size < s2n_rsa_public_encrypted_size(key)) {
        S2N_ERROR(S2N_ERR_NOMEM);
    }

    int r = RSA_public_encrypt(in->size, (unsigned char *)in->data, (unsigned char *)out->data, key->rsa, RSA_PKCS1_PADDING);
    if (r != out->size) {
        S2N_ERROR(S2N_ERR_SIZE_MISMATCH);
    }

    return 0;
}

static int s2n_rsa_decrypt(const struct s2n_pkey *priv, struct s2n_blob *in, struct s2n_blob *out)
{
    unsigned char intermediate[4096];
    const s2n_rsa_private_key *key = &priv->key.rsa_key;

    if (s2n_rsa_private_encrypted_size(key) > sizeof(intermediate)) {
        S2N_ERROR(S2N_ERR_NOMEM);
    }

    if (out->size > sizeof(intermediate)) {
        S2N_ERROR(S2N_ERR_NOMEM);
    }

    int r = RSA_private_decrypt(in->size, (unsigned char *)in->data, intermediate, key->rsa, RSA_PKCS1_PADDING);
    GUARD(s2n_constant_time_copy_or_dont(out->data, intermediate, out->size, r != out->size));
    if (r != out->size) {
        S2N_ERROR(S2N_ERR_SIZE_MISMATCH);
    }

    return 0;
}

static int s2n_rsa_keys_match(const struct s2n_pkey *pub, const struct s2n_pkey *priv)
{
    uint8_t plain_inpad[36] = {0}, plain_outpad[36] = {0}, encpad[8192];
    struct s2n_blob plain_in, plain_out, enc;

    const s2n_rsa_public_key *pub_key = &pub->key.rsa_key;
    const s2n_rsa_private_key *priv_key = &priv->key.rsa_key;
    notnull_check(pub_key);
    notnull_check(priv_key);

    plain_in.data = plain_inpad;
    plain_in.size = sizeof(plain_inpad);
    GUARD(s2n_get_private_random_data(&plain_in));

    enc.data = encpad;
    enc.size = s2n_rsa_public_encrypted_size(pub_key);
    lte_check(enc.size, sizeof(encpad));
    GUARD(s2n_rsa_encrypt(pub, &plain_in, &enc));

    plain_out.data = plain_outpad;
    plain_out.size = sizeof(plain_outpad);
    GUARD(s2n_rsa_decrypt(priv, &enc, &plain_out));

    if (memcmp(plain_in.data, plain_out.data, plain_in.size)) {
        S2N_ERROR(S2N_ERR_KEY_MISMATCH);
    }

    return 0;
}

static int s2n_rsa_key_free(struct s2n_pkey *pkey)
{
    struct s2n_rsa_key *rsa_key = &pkey->key.rsa_key;
    if (rsa_key->rsa == NULL) {
        return 0;
    }

    RSA_free(rsa_key->rsa);
    rsa_key->rsa = NULL;
    
    return 0;
}

int s2n_rsa_check_key_exists(const struct s2n_pkey *pkey)
{
    const struct s2n_rsa_key *rsa_key = &pkey->key.rsa_key;
    notnull_check(rsa_key->rsa);
    return 0;
}

int s2n_evp_pkey_to_rsa_public_key(s2n_rsa_public_key *rsa_key, EVP_PKEY *evp_public_key)
{
    RSA *rsa = EVP_PKEY_get1_RSA(evp_public_key);
    if (rsa == NULL) {
        S2N_ERROR(S2N_ERR_DECODE_CERTIFICATE);
    }
    
    rsa_key->rsa = rsa;
    return 0;
}

int s2n_evp_pkey_to_rsa_private_key(s2n_rsa_private_key *rsa_key, EVP_PKEY *evp_private_key)
{

    RSA *rsa = EVP_PKEY_get1_RSA(evp_private_key);
    if (rsa == NULL) {
        S2N_ERROR(S2N_ERR_DECODE_PRIVATE_KEY);
    }
    
    if (!RSA_check_key(rsa)) {
        RSA_free(rsa);
        S2N_ERROR(S2N_ERR_KEY_CHECK);
    }

    rsa_key->rsa = rsa;
    return 0;
}

int s2n_rsa_pkey_init(struct s2n_pkey *pkey) {
    pkey->sign = &s2n_rsa_sign;
    pkey->verify = &s2n_rsa_verify;
    pkey->encrypt = &s2n_rsa_encrypt;
    pkey->decrypt = &s2n_rsa_decrypt;
    pkey->match = &s2n_rsa_keys_match;
    pkey->free = &s2n_rsa_key_free;
    return 0;
}

