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

#include "crypto/s2n_pkey.h"

#include <openssl/evp.h>

#include "crypto/s2n_openssl_evp.h"
#include "crypto/s2n_openssl_x509.h"
#include "crypto/s2n_rsa_pss.h"
#include "error/s2n_errno.h"
#include "utils/s2n_result.h"
#include "utils/s2n_safety.h"

#define S2N_MAX_ALLOWED_CERT_TRAILING_BYTES 3

int s2n_pkey_zero_init(struct s2n_pkey *pkey)
{
    pkey->pkey = NULL;
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

int s2n_pkey_setup_for_type(struct s2n_pkey *pkey, s2n_pkey_type pkey_type)
{
    switch (pkey_type) {
        case S2N_PKEY_TYPE_RSA:
            return s2n_rsa_pkey_init(pkey);
        case S2N_PKEY_TYPE_ECDSA:
            return s2n_ecdsa_pkey_init(pkey);
        case S2N_PKEY_TYPE_RSA_PSS:
            return s2n_rsa_pss_pkey_init(pkey);
        case S2N_PKEY_TYPE_SENTINEL:
        case S2N_PKEY_TYPE_UNKNOWN:
            POSIX_BAIL(S2N_ERR_CERT_TYPE_UNSUPPORTED);
    }
    POSIX_BAIL(S2N_ERR_CERT_TYPE_UNSUPPORTED);
}

int s2n_pkey_check_key_exists(const struct s2n_pkey *pkey)
{
    POSIX_ENSURE_REF(pkey->pkey);
    POSIX_ENSURE_REF(pkey->check_key);

    return pkey->check_key(pkey);
}

S2N_RESULT s2n_pkey_size(const struct s2n_pkey *pkey, uint32_t *size_out)
{
    RESULT_ENSURE_REF(pkey);
    RESULT_ENSURE_REF(pkey->size);
    RESULT_ENSURE_REF(size_out);

    RESULT_GUARD(pkey->size(pkey, size_out));

    return S2N_RESULT_OK;
}

int s2n_pkey_sign(const struct s2n_pkey *pkey, s2n_signature_algorithm sig_alg,
        struct s2n_hash_state *digest, struct s2n_blob *signature)
{
    POSIX_ENSURE_REF(pkey->sign);

    return pkey->sign(pkey, sig_alg, digest, signature);
}

int s2n_pkey_verify(const struct s2n_pkey *pkey, s2n_signature_algorithm sig_alg,
        struct s2n_hash_state *digest, struct s2n_blob *signature)
{
    POSIX_ENSURE_REF(pkey);
    POSIX_ENSURE_REF(pkey->verify);

    return pkey->verify(pkey, sig_alg, digest, signature);
}

int s2n_pkey_encrypt(const struct s2n_pkey *pkey, struct s2n_blob *in, struct s2n_blob *out)
{
    POSIX_ENSURE_REF(pkey->encrypt);

    return pkey->encrypt(pkey, in, out);
}

int s2n_pkey_decrypt(const struct s2n_pkey *pkey, struct s2n_blob *in, struct s2n_blob *out)
{
    POSIX_ENSURE_REF(pkey->decrypt);

    return pkey->decrypt(pkey, in, out);
}

int s2n_pkey_match(const struct s2n_pkey *pub_key, const struct s2n_pkey *priv_key)
{
    POSIX_ENSURE_REF(pub_key->match);

    S2N_ERROR_IF(pub_key->match != priv_key->match, S2N_ERR_KEY_MISMATCH);

    return pub_key->match(pub_key, priv_key);
}

int s2n_pkey_free(struct s2n_pkey *key)
{
    if (key != NULL && key->free != NULL) {
        POSIX_GUARD(key->free(key));
    }

    if (key->pkey != NULL) {
        EVP_PKEY_free(key->pkey);
        key->pkey = NULL;
    }

    return S2N_SUCCESS;
}

int s2n_asn1der_to_private_key(struct s2n_pkey *priv_key, struct s2n_blob *asn1der, int type_hint)
{
    const unsigned char *key_to_parse = asn1der->data;

    /* We use "d2i_AutoPrivateKey" instead of "PEM_read_bio_PrivateKey" because
     * s2n-tls prefers to perform its own custom PEM parsing. Historically,
     * openssl's PEM parsing tended to ignore invalid certificates rather than
     * error on them. We prefer to fail early rather than continue without
     * the full and correct chain intended by the application.
     */
    DEFER_CLEANUP(EVP_PKEY *evp_private_key = d2i_AutoPrivateKey(NULL, &key_to_parse, asn1der->size),
            EVP_PKEY_free_pointer);

    /* We have found cases where d2i_AutoPrivateKey fails to detect the type of
     * the key. For example, openssl fails to identify an EC key without the
     * optional publicKey field.
     *
     * If d2i_AutoPrivateKey fails, try once more with the type we parsed from the PEM.
     */
    if (evp_private_key == NULL) {
        evp_private_key = d2i_PrivateKey(type_hint, NULL, &key_to_parse, asn1der->size);
    }
    POSIX_ENSURE(evp_private_key, S2N_ERR_DECODE_PRIVATE_KEY);

    /* If key parsing is successful, d2i_AutoPrivateKey increments *key_to_parse to the byte following the parsed data */
    uint32_t parsed_len = key_to_parse - asn1der->data;
    if (parsed_len != asn1der->size) {
        POSIX_BAIL(S2N_ERR_DECODE_PRIVATE_KEY);
    }

    /* Initialize s2n_pkey according to key type */
    int type = EVP_PKEY_base_id(evp_private_key);

    int ret;
    switch (type) {
        case EVP_PKEY_RSA:
            ret = s2n_rsa_pkey_init(priv_key);
            if (ret != 0) {
                break;
            }
            ret = s2n_evp_pkey_to_rsa_private_key(&priv_key->key.rsa_key, evp_private_key);
            break;
        case EVP_PKEY_RSA_PSS:
            ret = s2n_rsa_pss_pkey_init(priv_key);
            if (ret != 0) {
                break;
            }
            ret = s2n_evp_pkey_to_rsa_pss_private_key(&priv_key->key.rsa_key, evp_private_key);
            break;
        case EVP_PKEY_EC:
            ret = s2n_ecdsa_pkey_init(priv_key);
            if (ret != 0) {
                break;
            }
            ret = s2n_evp_pkey_to_ecdsa_private_key(&priv_key->key.ecdsa_key, evp_private_key);
            break;
        default:
            POSIX_BAIL(S2N_ERR_DECODE_PRIVATE_KEY);
    }

    priv_key->pkey = evp_private_key;
    /* Reset to avoid DEFER_CLEANUP freeing our key */
    evp_private_key = NULL;

    return ret;
}

int s2n_asn1der_to_public_key_and_type(struct s2n_pkey *pub_key, s2n_pkey_type *pkey_type_out, struct s2n_blob *asn1der)
{
    uint8_t *cert_to_parse = asn1der->data;
    DEFER_CLEANUP(X509 *cert = NULL, X509_free_pointer);

    cert = d2i_X509(NULL, (const unsigned char **) (void *) &cert_to_parse, asn1der->size);
    S2N_ERROR_IF(cert == NULL, S2N_ERR_DECODE_CERTIFICATE);

    /* If cert parsing is successful, d2i_X509 increments *cert_to_parse to the byte following the parsed data */
    uint32_t parsed_len = cert_to_parse - asn1der->data;

    /* Some TLS clients in the wild send extra trailing bytes after the Certificate.
     * Allow this in s2n for backwards compatibility with existing clients. */
    uint32_t trailing_bytes = asn1der->size - parsed_len;
    POSIX_ENSURE(trailing_bytes <= S2N_MAX_ALLOWED_CERT_TRAILING_BYTES, S2N_ERR_DECODE_CERTIFICATE);

    DEFER_CLEANUP(EVP_PKEY *evp_public_key = X509_get_pubkey(cert), EVP_PKEY_free_pointer);
    S2N_ERROR_IF(evp_public_key == NULL, S2N_ERR_DECODE_CERTIFICATE);

    /* Check for success in decoding certificate according to type */
    int type = EVP_PKEY_base_id(evp_public_key);

    int ret;
    switch (type) {
        case EVP_PKEY_RSA:
            ret = s2n_rsa_pkey_init(pub_key);
            if (ret != 0) {
                break;
            }
            ret = s2n_evp_pkey_to_rsa_public_key(&pub_key->key.rsa_key, evp_public_key);
            *pkey_type_out = S2N_PKEY_TYPE_RSA;
            break;
        case EVP_PKEY_RSA_PSS:
            ret = s2n_rsa_pss_pkey_init(pub_key);
            if (ret != 0) {
                break;
            }
            ret = s2n_evp_pkey_to_rsa_pss_public_key(&pub_key->key.rsa_key, evp_public_key);
            *pkey_type_out = S2N_PKEY_TYPE_RSA_PSS;
            break;
        case EVP_PKEY_EC:
            ret = s2n_ecdsa_pkey_init(pub_key);
            if (ret != 0) {
                break;
            }
            ret = s2n_evp_pkey_to_ecdsa_public_key(&pub_key->key.ecdsa_key, evp_public_key);
            *pkey_type_out = S2N_PKEY_TYPE_ECDSA;
            break;
        default:
            POSIX_BAIL(S2N_ERR_DECODE_CERTIFICATE);
    }

    pub_key->pkey = evp_public_key;
    /* Reset to avoid DEFER_CLEANUP freeing our key */
    evp_public_key = NULL;

    return ret;
}
