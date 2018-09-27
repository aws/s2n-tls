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

int s2n_pkey_zero_init(struct s2n_pkey *pkey) 
{
    pkey->size = NULL;
    pkey->sign = NULL;
    pkey->verify = NULL;
    pkey->encrypt = NULL;
    pkey->decrypt = NULL;
    pkey->match = NULL;
    pkey->free = NULL;
    pkey->check_key = NULL;
    return 0;
}

int s2n_pkey_setup_for_type(struct s2n_pkey *pkey, s2n_cert_type cert_type)
{
    switch(cert_type){
    case S2N_CERT_TYPE_RSA_SIGN:
        //printf("OMG ss2n_pkey_setup_for_type \n");
        GUARD(s2n_rsa_pkey_init(pkey));
        //printf("OMG ss2n_pkey_setup_for_type passed \n");
        break;
    case S2N_CERT_TYPE_ECDSA_SIGN:
        GUARD(s2n_ecdsa_pkey_init(pkey));
        break;
    default:
        S2N_ERROR(S2N_ERR_DECODE_CERTIFICATE);
    }
    return 0;
}

int s2n_pkey_check_key_exists(const struct s2n_pkey *pkey)
{
    notnull_check(pkey->check_key);

    return pkey->check_key(pkey);
}

int s2n_pkey_size(const struct s2n_pkey *pkey)
{
    notnull_check(pkey->size);

    return pkey->size(pkey);
}

int s2n_pkey_sign(const struct s2n_pkey *pkey, struct s2n_hash_state *digest, struct s2n_blob *signature)
{
    notnull_check(pkey->sign);
    return pkey->sign(pkey, digest, signature);
}

int s2n_pkey_verify(const struct s2n_pkey *pkey, struct s2n_hash_state *digest, struct s2n_blob *signature)
{
    notnull_check(pkey);
    notnull_check(pkey->verify);
    return pkey->verify(pkey, digest, signature);
}

int s2n_pkey_encrypt(const struct s2n_pkey *pkey, struct s2n_blob *in, struct s2n_blob *out)
{
    notnull_check(pkey->encrypt);

    return pkey->encrypt(pkey, in, out);
}

int s2n_pkey_decrypt(const struct s2n_pkey *pkey, struct s2n_blob *in, struct s2n_blob *out)
{
    notnull_check(pkey->decrypt);

    return pkey->decrypt(pkey, in, out);
}

int s2n_pkey_match(const struct s2n_pkey *pub_key, const struct s2n_pkey *priv_key)
{
    notnull_check(pub_key->match);

    return pub_key->match(pub_key, priv_key);
}

int s2n_pkey_free(struct s2n_pkey *pkey)
{
    if (pkey == NULL || pkey->free == NULL) {
        return 0;
    }
    return pkey->free(pkey);
}

int s2n_asn1der_to_private_key(struct s2n_pkey *priv_key, struct s2n_blob *asn1der)
{
    uint8_t *key_to_parse = asn1der->data;

    /* Detect key type */
    EVP_PKEY *evp_private_key = d2i_AutoPrivateKey(NULL, (const unsigned char **)(void *)&key_to_parse, asn1der->size);
    S2N_ERROR_IF(evp_private_key == NULL, S2N_ERR_DECODE_PRIVATE_KEY);
    
    /* If key parsing is successful, d2i_AutoPrivateKey increments *key_to_parse to the byte following the parsed data */
    uint32_t parsed_len = key_to_parse - asn1der->data;
    if (parsed_len != asn1der->size) {
        EVP_PKEY_free(evp_private_key);
        S2N_ERROR(S2N_ERR_DECODE_PRIVATE_KEY);
    }

    /* Initialize s2n_pkey according to key type */
    int type = EVP_PKEY_base_id(evp_private_key);
    
    int ret;
    switch (type) {
    case EVP_PKEY_RSA:
        //printf("OMG s2n_asnlder_to_proivate_key \n");
        ret = s2n_rsa_pkey_init(priv_key);
        if (ret != 0) {
            break;
        }
        ret = s2n_evp_pkey_to_rsa_private_key(&priv_key->key.rsa_key, evp_private_key);
        break;
    case EVP_PKEY_EC:
        ret = s2n_ecdsa_pkey_init(priv_key);
        if (ret != 0) {
            break;
        }
        ret = s2n_evp_pkey_to_ecdsa_private_key(&priv_key->key.ecdsa_key, evp_private_key);
        break;
    default:
        EVP_PKEY_free(evp_private_key);
        S2N_ERROR(S2N_ERR_DECODE_PRIVATE_KEY);
    }
    
    EVP_PKEY_free(evp_private_key);
    
    return ret;
}

int s2n_asn1der_to_public_key_and_type(struct s2n_pkey *pub_key, s2n_cert_type *cert_type_out, struct s2n_blob *asn1der)
{
    uint8_t *cert_to_parse = asn1der->data;
    
    X509 *cert = d2i_X509(NULL, (const unsigned char **)(void *)&cert_to_parse, asn1der->size);
    S2N_ERROR_IF(cert == NULL, S2N_ERR_DECODE_CERTIFICATE);
    
    /* If cert parsing is successful, d2i_X509 increments *cert_to_parse to the byte following the parsed data */
    uint32_t parsed_len = cert_to_parse - asn1der->data;
    if (parsed_len != asn1der->size) {
        X509_free(cert);
        S2N_ERROR(S2N_ERR_DECODE_CERTIFICATE);
    }

    EVP_PKEY *evp_public_key = X509_get_pubkey(cert);
    X509_free(cert);

    S2N_ERROR_IF(evp_public_key == NULL, S2N_ERR_DECODE_CERTIFICATE);

    /* Check for success in decoding certificate according to type */
    int type = EVP_PKEY_base_id(evp_public_key);
    
    int ret;
    switch (type) {
    case EVP_PKEY_RSA:
        //printf("OMG s2n_asn1der_to_public_key_and_type\n");
        ret = s2n_rsa_pkey_init(pub_key);
        if (ret != 0) {
            break;
        }
        ret = s2n_evp_pkey_to_rsa_public_key(&pub_key->key.rsa_key, evp_public_key);
        *cert_type_out = S2N_CERT_TYPE_RSA_SIGN; 
        break;
    case EVP_PKEY_EC:
        ret = s2n_ecdsa_pkey_init(pub_key);
        if (ret != 0) {
            break;
        }
        ret = s2n_evp_pkey_to_ecdsa_public_key(&pub_key->key.ecdsa_key, evp_public_key);
        *cert_type_out = S2N_CERT_TYPE_ECDSA_SIGN; 
        break;
    default:
        EVP_PKEY_free(evp_public_key);
        S2N_ERROR(S2N_ERR_DECODE_CERTIFICATE);
    }
    
    EVP_PKEY_free(evp_public_key);
    
    return ret;
}

