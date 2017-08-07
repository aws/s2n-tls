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

int s2n_ecdsa_sign(const struct s2n_ecdsa_private_key *key, struct s2n_hash_state *digest, struct s2n_blob *signature)
{
    uint8_t digest_length;
    GUARD(s2n_hash_digest_size(digest->alg, &digest_length));
    lte_check(digest_length, MAX_DIGEST_LENGTH);

    uint8_t digest_out[MAX_DIGEST_LENGTH];
    GUARD(s2n_hash_digest(digest, digest_out, digest_length));

    unsigned int signature_size = signature->size;
    if (ECDSA_sign(0, digest_out, digest_length, signature->data, &signature_size, key->eckey) == 0) {
        S2N_ERROR(S2N_ERR_SIGN);
    }
    if (signature_size > signature->size) {
        S2N_ERROR(S2N_ERR_SIZE_MISMATCH);
    }
    signature->size = signature_size;

    GUARD(s2n_hash_reset(digest));
    
    return 0;
}

int s2n_ecdsa_verify(const struct s2n_ecdsa_public_key *key, struct s2n_hash_state *digest, struct s2n_blob *signature)
{
    uint8_t digest_length;
    GUARD(s2n_hash_digest_size(digest->alg, &digest_length));
    lte_check(digest_length, MAX_DIGEST_LENGTH);

    uint8_t digest_out[MAX_DIGEST_LENGTH];
    GUARD(s2n_hash_digest(digest, digest_out, digest_length));
    
    /* ECDSA_verify ignores the first parameter */
    if (ECDSA_verify(0, digest_out, digest_length, signature->data, signature->size, key->eckey) == 0) {
        S2N_ERROR(S2N_ERR_VERIFY_SIGNATURE);
    }

    GUARD(s2n_hash_reset(digest));
    
    return 0;
}

int s2n_asn1der_to_ecdsa_public_key(struct s2n_ecdsa_public_key *key, struct s2n_blob *asn1der)
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

    if (EVP_PKEY_base_id(public_key) != EVP_PKEY_EC) {
        EVP_PKEY_free(public_key);
        S2N_ERROR(S2N_ERR_DECODE_CERTIFICATE);
    }

    key->eckey = EVP_PKEY_get1_EC_KEY(public_key);
    if (key->eckey == NULL) {
        EVP_PKEY_free(public_key);
        S2N_ERROR(S2N_ERR_DECODE_CERTIFICATE);
    }

    EVP_PKEY_free(public_key);

    return 0;
}

int s2n_asn1der_to_ecdsa_private_key(struct s2n_ecdsa_private_key *key, struct s2n_blob *asn1der)
{
    uint8_t *key_to_parse = asn1der->data;

    EVP_PKEY *pkey = d2i_PrivateKey(EVP_PKEY_EC, NULL, (const unsigned char **)(void *)&key_to_parse, asn1der->size);
    if (pkey == NULL) {
        S2N_ERROR(S2N_ERR_DECODE_PRIVATE_KEY);
    }
    
    EC_KEY *ec_key = EVP_PKEY_get1_EC_KEY(pkey);
    EVP_PKEY_free(pkey);
    if (ec_key == NULL) {
        S2N_ERROR(S2N_ERR_DECODE_PRIVATE_KEY);
    }

    /* If key parsing is successful, d2i_PrivateKey increments *key_to_parse to the byte following the parsed data */
    uint32_t parsed_len = key_to_parse - asn1der->data;
    if (parsed_len != asn1der->size) {
        S2N_ERROR(S2N_ERR_DECODE_PRIVATE_KEY);
    }

    if (!EC_KEY_check_key(ec_key)) {
        S2N_ERROR(S2N_ERR_PRIVATE_KEY_CHECK);
    }

    key->eckey = ec_key;

    return 0;

}

int s2n_ecdsa_public_key_free(struct s2n_ecdsa_public_key *key)
{
    EC_KEY_free(key->eckey);
    key->eckey = NULL;
    return 0;
}

int s2n_ecdsa_private_key_free(struct s2n_ecdsa_private_key *key)
{
    EC_KEY_free(key->eckey);
    key->eckey = NULL;
    return 0;
}

int s2n_ecdsa_signature_size(const struct s2n_ecdsa_private_key *key)
{
    notnull_check(key->eckey);

    return ECDSA_size(key->eckey);
}

int s2n_ecdsa_keys_match(const struct s2n_ecdsa_public_key *pub_key, const struct s2n_ecdsa_private_key *priv_key)
{
    uint8_t input[16];
    struct s2n_blob random_input;
    struct s2n_blob signature;
    struct s2n_hash_state state_in, state_out;

    random_input.data = input;
    random_input.size = sizeof(input);
    GUARD(s2n_get_public_random_data(&random_input));

    /* s2n_hash_new only allocates memory when using high-level EVP hashes, currently restricted to FIPS mode. */
    GUARD(s2n_hash_new(&state_in));
    GUARD(s2n_hash_new(&state_out));

    GUARD(s2n_hash_init(&state_in, S2N_HASH_SHA1));
    GUARD(s2n_hash_init(&state_out, S2N_HASH_SHA1));
    GUARD(s2n_hash_update(&state_in, input, sizeof(input)));
    GUARD(s2n_hash_update(&state_out, input, sizeof(input)));

    GUARD(s2n_alloc(&signature, s2n_ecdsa_signature_size(priv_key)));
    
    GUARD(s2n_ecdsa_sign(priv_key, &state_in, &signature));
    GUARD(s2n_ecdsa_verify(pub_key, &state_out, &signature));

    GUARD(s2n_hash_free(&state_in));
    GUARD(s2n_hash_free(&state_out));

    return 0;
}
