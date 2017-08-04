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

#include <openssl/evp.h>
#include <openssl/x509.h>

#include "error/s2n_errno.h"

#include "crypto/s2n_pkey.h"

#include "utils/s2n_safety.h"

int s2n_asn1der_to_private_key(struct s2n_pkey *priv_key, struct s2n_blob *asn1der)
{
    int ret;
    uint8_t *key_to_parse = asn1der->data;

    /* Detect key type */
    EVP_PKEY *pkey = d2i_AutoPrivateKey(NULL, (const unsigned char **)(void *)&key_to_parse, asn1der->size);
    if (pkey == NULL) {
        S2N_ERROR(S2N_ERR_DECODE_PRIVATE_KEY);
    }
    
    /* If key parsing is successful, d2i_AutoPrivateKey increments *key_to_parse to the byte following the parsed data */
    uint32_t parsed_len = key_to_parse - asn1der->data;
    if (parsed_len != asn1der->size) {
        EVP_PKEY_free(pkey);
        S2N_ERROR(S2N_ERR_DECODE_PRIVATE_KEY);
    }

    int type = EVP_PKEY_type(EVP_PKEY_id(pkey));
    
    /* Initialize s2n_pkey according to key type */
    switch (type) {
    case EVP_PKEY_RSA:
        ret = s2n_pkey_to_rsa_private_key(&priv_key->key.rsa_key, pkey);
        priv_key->ctx = &rsa_key_ctx;
        break;
    case EVP_PKEY_EC:
        ret = s2n_pkey_to_ecdsa_private_key(&priv_key->key.ecdsa_key, pkey);
        priv_key->ctx = &ecdsa_key_ctx;
        break;
    default:
        EVP_PKEY_free(pkey);
        S2N_ERROR(S2N_ERR_DECODE_PRIVATE_KEY);
    }
    
    EVP_PKEY_free(pkey);
    
    return ret;
}

int s2n_asn1der_to_public_key(struct s2n_pkey *pub_key, struct s2n_blob *asn1der)
{
    int ret;
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

    EVP_PKEY *pkey = X509_get_pubkey(cert);
    X509_free(cert);

    if (pkey == NULL) {
        S2N_ERROR(S2N_ERR_DECODE_CERTIFICATE);
    }

    /* Check for success in decoding certificate according to type*/
    int type = EVP_PKEY_base_id(pkey);
    
    switch (type) {
    case EVP_PKEY_RSA:
        ret = s2n_pkey_to_rsa_public_key(&pub_key->key.rsa_key, pkey);
        pub_key->ctx = &rsa_key_ctx;
        break;
    case EVP_PKEY_EC:
        ret = s2n_pkey_to_ecdsa_public_key(&pub_key->key.ecdsa_key, pkey);
        pub_key->ctx = &ecdsa_key_ctx;
        break;
    default:
        EVP_PKEY_free(pkey);
        S2N_ERROR(S2N_ERR_DECODE_CERTIFICATE);
    }
    
    EVP_PKEY_free(pkey);
    
    return ret;
}

int s2n_pkey_sign(const struct s2n_pkey *pkey, struct s2n_hash_state *digest, struct s2n_blob *signature)
{
    notnull_check(pkey->ctx->sign);
    
    return pkey->ctx->sign(pkey, digest, signature);
}

int s2n_pkey_verify(const struct s2n_pkey *pkey, struct s2n_hash_state *digest, struct s2n_blob *signature)
{
    notnull_check(pkey->ctx->verify);
    
    return pkey->ctx->verify(pkey, digest, signature);
}

int s2n_pkey_encrypt(const struct s2n_pkey *pkey, struct s2n_blob *in, struct s2n_blob *out)
{
    notnull_check(pkey->ctx->encrypt);

    return pkey->ctx->encrypt(pkey, in, out);
}

int s2n_pkey_decrypt(const struct s2n_pkey *pkey, struct s2n_blob *in, struct s2n_blob *out)
{
    notnull_check(pkey->ctx->decrypt);

    return pkey->ctx->decrypt(pkey, in, out);
}

int s2n_pkey_match(const struct s2n_pkey *pub_key, const struct s2n_pkey *priv_key)
{
    return pub_key->ctx->match(pub_key, priv_key);
}

int s2n_pkey_free(struct s2n_pkey *pkey)
{
    if (pkey == NULL || pkey->ctx == NULL) {
        return 0;
    }

    return pkey->ctx->free(pkey);
}
