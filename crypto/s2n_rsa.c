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

#include "stuffer/s2n_stuffer.h"

#include "crypto/s2n_hash.h"
#include "crypto/s2n_rsa.h"

#include "utils/s2n_random.h"
#include "utils/s2n_safety.h"
#include "utils/s2n_blob.h"

int s2n_asn1der_to_rsa_public_key(struct s2n_rsa_public_key *key, struct s2n_blob *asn1der, const char **err)
{
    uint8_t *original_ptr = asn1der->data;
    X509 *cert = d2i_X509(NULL, (const unsigned char **)(void *)&asn1der->data, asn1der->size);
    if (cert == NULL) {
        *err = "Could not decode server certificate";
        return -1;
    }
    if (asn1der->data - original_ptr != asn1der->size) {
        *err = "Extraneous data in certificate";
        return -1;
    }
    asn1der->data = original_ptr;

    EVP_PKEY *public_key = X509_get_pubkey(cert);
    if (public_key == NULL) {
        *err = "Could not extract public key from certificate";
        return -1;
    }

    if (public_key->type != EVP_PKEY_RSA) {
        *err = "Certificate does not have an RSA public key";
        return -1;
    }

    key->rsa = EVP_PKEY_get1_RSA(public_key);
    if (key->rsa == NULL) {
        *err = "Could not decode RSA public key from certificate";
        return -1;
    }

    EVP_PKEY_free(public_key);
    X509_free(cert);

    return 0;
}

int s2n_asn1der_to_rsa_private_key(struct s2n_rsa_private_key *key, struct s2n_blob *asn1der, const char **err)
{
    uint8_t *original_ptr = asn1der->data;

    key->rsa = d2i_RSAPrivateKey(NULL, (const unsigned char **)(void *)&asn1der->data, asn1der->size);
    if (key->rsa == NULL) {
        *err = "Could not decode the private key";
        return -1;
    }
    if (asn1der->data - original_ptr != asn1der->size) {
        *err = "Extraneous data in the private key";
        return -1;
    }

    return 0;
}

int s2n_rsa_public_key_free(struct s2n_rsa_public_key *key, const char **err)
{
    RSA_free(key->rsa);
    return 0;
}

int s2n_rsa_private_key_free(struct s2n_rsa_private_key *key, const char **err)
{
    RSA_free(key->rsa);
    return 0;
}

int s2n_rsa_public_encrypted_size(struct s2n_rsa_public_key *key, const char **err)
{
    return RSA_size(key->rsa);
}

int s2n_rsa_private_encrypted_size(struct s2n_rsa_private_key *key, const char **err)
{
    return RSA_size(key->rsa);
}

int s2n_rsa_sign(struct s2n_rsa_private_key *key, struct s2n_hash_state *digest, struct s2n_blob *signature, const char **err)
{
    uint8_t digest_out[MD5_DIGEST_LENGTH + SHA_DIGEST_LENGTH];

    int type, digest_length;
    if (digest->alg == S2N_HASH_MD5_SHA1) {
        type = NID_md5_sha1;
        digest_length = MD5_DIGEST_LENGTH + SHA_DIGEST_LENGTH;
    } else if (digest->alg == S2N_HASH_SHA1) {
        type = NID_sha1;
        digest_length = SHA_DIGEST_LENGTH;
    } else {
        *err = "Invalid RSA hash type";
        return -1;
    }

    GUARD(s2n_hash_digest(digest, digest_out, digest_length, err));

    unsigned int signature_size = signature->size;
    if (RSA_sign(type, digest_out, digest_length, signature->data, &signature_size, key->rsa) == 0) {
        *err = "Failed to sign digest";
        return -1;
    }
    if (signature_size > signature->size) {
        *err = "Mismatch between signature sizes";
    }
    signature->size = signature_size;

    return 0;
}

int s2n_rsa_verify(struct s2n_rsa_public_key *key, struct s2n_hash_state *digest, struct s2n_blob *signature, const char **err)
{
    uint8_t digest_out[MD5_DIGEST_LENGTH + SHA_DIGEST_LENGTH];

    int type, digest_length;
    if (digest->alg == S2N_HASH_MD5_SHA1) {
        type = NID_md5_sha1;
        digest_length = MD5_DIGEST_LENGTH + SHA_DIGEST_LENGTH;
    } else if (digest->alg == S2N_HASH_SHA1) {
        type = NID_sha1;
        digest_length = SHA_DIGEST_LENGTH;
    } else {
        *err = "Invalid RSA hash type";
        return -1;
    }

    GUARD(s2n_hash_digest(digest, digest_out, digest_length, err));

    if (RSA_verify(type, digest_out, digest_length, signature->data, signature->size, key->rsa) == 0) {
        *err = "Failed to verify digest";
        return -1;
    }

    return 0;
}

int s2n_rsa_encrypt(struct s2n_rsa_public_key *key, struct s2n_blob *in, struct s2n_blob *out, const char **err)
{
    int r = RSA_public_encrypt(in->size, (unsigned char *)in->data, (unsigned char *)out->data, key->rsa, RSA_PKCS1_PADDING);
    if (r != out->size) {
        *err = "Mismatch between predicted and actual encrypted sizes";
        return -1;
    }

    return 0;
}

int s2n_rsa_decrypt(struct s2n_rsa_private_key *key, struct s2n_blob *in, struct s2n_blob *out, const char **err)
{
    int r = RSA_private_decrypt(in->size, (unsigned char *)in->data, (unsigned char *)out->data, key->rsa, RSA_PKCS1_PADDING);
    if (r != out->size) {
        *err = "Mismatch between predicted and actual decrypted sizes";
        return -1;
    }

    return 0;
}

int s2n_rsa_keys_match(struct s2n_rsa_public_key *pub, struct s2n_rsa_private_key *priv, const char **err)
{
    uint8_t plain_inpad[36], plain_outpad[36], encpad[8192];
    struct s2n_blob plain_in, plain_out, enc;

    plain_in.data = plain_inpad;
    plain_in.size = sizeof(plain_inpad);
    GUARD(s2n_get_random_data(plain_in.data, plain_in.size, err));

    enc.data = encpad;
    enc.size = s2n_rsa_public_encrypted_size(pub, err);
    lte_check(enc.size, sizeof(encpad));
    GUARD(s2n_rsa_encrypt(pub, &plain_in, &enc, err));

    plain_out.data = plain_outpad;
    plain_out.size = sizeof(plain_outpad);
    GUARD(s2n_rsa_decrypt(priv, &enc, &plain_out, err));

    if (memcmp(plain_in.data, plain_out.data, plain_in.size)) {
        *err = "Public and private keys do not match";
        return -1;
    }

    return 0;
}
