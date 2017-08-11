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

#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <stdint.h>

#include "error/s2n_errno.h"

#include "stuffer/s2n_stuffer.h"

#include "crypto/s2n_hash.h"
#include "crypto/s2n_openssl.h"
#include "crypto/s2n_rsa.h"

#include "utils/s2n_random.h"
#include "utils/s2n_safety.h"
#include "utils/s2n_blob.h"

int s2n_rsa_public_key_set_from_openssl(struct s2n_rsa_public_key *s2n_rsa, RSA *openssl_rsa)
{
    notnull_check(s2n_rsa);
    notnull_check(openssl_rsa);
    s2n_rsa->rsa = openssl_rsa;

    return 0;
}

int s2n_asn1der_to_rsa_public_key(struct s2n_rsa_public_key *key, struct s2n_blob *asn1der)
{
    uint8_t *cert_to_parse = asn1der->data;
    X509 *cert = d2i_X509(NULL, (const unsigned char **)(void *)&cert_to_parse, asn1der->size);
    if (cert == NULL) {
        S2N_ERROR(S2N_ERR_DECODE_CERTIFICATE);
    }
    /* If cert parsing is successful, d2i_X509 increments *cert_to_parse to the byte following the parsed data */
    uint32_t parsed_len = cert_to_parse - asn1der->data;

    if (parsed_len != asn1der->size) {
        X509_free(cert);
        S2N_ERROR(S2N_ERR_DECODE_CERTIFICATE);
    }

    EVP_PKEY *public_key = X509_get_pubkey(cert);
    X509_free(cert);

    if (public_key == NULL) {
        S2N_ERROR(S2N_ERR_DECODE_CERTIFICATE);
    }

    if (EVP_PKEY_base_id(public_key) != EVP_PKEY_RSA) {
        EVP_PKEY_free(public_key);
        S2N_ERROR(S2N_ERR_DECODE_CERTIFICATE);
    }

    key->rsa = EVP_PKEY_get1_RSA(public_key);
    if (key->rsa == NULL) {
        EVP_PKEY_free(public_key);
        S2N_ERROR(S2N_ERR_DECODE_CERTIFICATE);
    }

    EVP_PKEY_free(public_key);

    return 0;
}

int s2n_asn1der_to_rsa_private_key(struct s2n_rsa_private_key *key, struct s2n_blob *asn1der)
{
    uint8_t *cert_to_parse = asn1der->data;

    EVP_PKEY *pkey = d2i_PrivateKey(EVP_PKEY_RSA, NULL, (const unsigned char **)(void *)&cert_to_parse, asn1der->size);
    if (pkey == NULL) {
        S2N_ERROR(S2N_ERR_DECODE_PRIVATE_KEY);
    }
    RSA *rsa_key = EVP_PKEY_get1_RSA(pkey);
    EVP_PKEY_free(pkey);
    if (rsa_key == NULL) {
        S2N_ERROR(S2N_ERR_DECODE_PRIVATE_KEY);
    }

    /* If cert parsing is successful, d2i_RSAPrivateKey increments *cert_to_parse to the byte following the parsed data */
    uint32_t parsed_len = cert_to_parse - asn1der->data;
    if (parsed_len != asn1der->size) {
        S2N_ERROR(S2N_ERR_DECODE_PRIVATE_KEY);
    }

    if (!RSA_check_key(rsa_key)) {
        S2N_ERROR(S2N_ERR_PRIVATE_KEY_CHECK);
    }

    key->rsa = rsa_key;

    return 0;
}

int s2n_rsa_public_key_free(struct s2n_rsa_public_key *key)
{
    RSA_free(key->rsa);
    key->rsa = NULL;
    return 0;
}

int s2n_rsa_private_key_free(struct s2n_rsa_private_key *key)
{
    RSA_free(key->rsa);
    key->rsa = NULL;
    return 0;
}

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

int s2n_rsa_public_encrypted_size(struct s2n_rsa_public_key *key)
{
    notnull_check(key->rsa);
    GUARD(s2n_rsa_modulus_check(key->rsa));

    return RSA_size(key->rsa);
}

int s2n_rsa_private_encrypted_size(struct s2n_rsa_private_key *key)
{
    notnull_check(key->rsa);
    GUARD(s2n_rsa_modulus_check(key->rsa));

    return RSA_size(key->rsa);
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

int s2n_rsa_sign(struct s2n_rsa_private_key *key, struct s2n_hash_state *digest, struct s2n_blob *signature)
{
    uint8_t digest_length;
    int NID_type;
    GUARD(s2n_hash_digest_size(digest->alg, &digest_length));
    GUARD(s2n_hash_NID_type(digest->alg, &NID_type));
    lte_check(digest_length, MAX_DIGEST_LENGTH);

    uint8_t digest_out[MAX_DIGEST_LENGTH];
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

int s2n_rsa_verify(struct s2n_rsa_public_key *key, struct s2n_hash_state *digest, struct s2n_blob *signature)
{
    uint8_t digest_length;
    int NID_type;
    GUARD(s2n_hash_digest_size(digest->alg, &digest_length));
    GUARD(s2n_hash_NID_type(digest->alg, &NID_type));
    lte_check(digest_length, MAX_DIGEST_LENGTH);

    uint8_t digest_out[MAX_DIGEST_LENGTH];
    GUARD(s2n_hash_digest(digest, digest_out, digest_length));

    if (RSA_verify(NID_type, digest_out, digest_length, signature->data, signature->size, key->rsa) == 0) {
        S2N_ERROR(S2N_ERR_VERIFY_SIGNATURE);
    }

    return 0;
}

int s2n_rsa_encrypt(struct s2n_rsa_public_key *key, struct s2n_blob *in, struct s2n_blob *out)
{
    if (out->size < s2n_rsa_public_encrypted_size(key)) {
        S2N_ERROR(S2N_ERR_NOMEM);
    }

    int r = RSA_public_encrypt(in->size, (unsigned char *)in->data, (unsigned char *)out->data, key->rsa, RSA_PKCS1_PADDING);
    if (r != out->size) {
        S2N_ERROR(S2N_ERR_SIZE_MISMATCH);
    }

    return 0;
}

int s2n_rsa_decrypt(struct s2n_rsa_private_key *key, struct s2n_blob *in, struct s2n_blob *out)
{
    unsigned char intermediate[4096];
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

int s2n_rsa_keys_match(struct s2n_rsa_public_key *pub, struct s2n_rsa_private_key *priv)
{
    uint8_t plain_inpad[36], plain_outpad[36], encpad[8192];
    struct s2n_blob plain_in, plain_out, enc;

    plain_in.data = plain_inpad;
    plain_in.size = sizeof(plain_inpad);
    GUARD(s2n_get_private_random_data(&plain_in));

    enc.data = encpad;
    enc.size = s2n_rsa_public_encrypted_size(pub);
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
