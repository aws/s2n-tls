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

#include <openssl/aes.h>
#include <openssl/evp.h>

#include "crypto/s2n_cipher.h"

#include "utils/s2n_safety.h"
#include "utils/s2n_blob.h"

static const int s2n_aes_gcm_iv_len = EVP_GCM_TLS_EXPLICIT_IV_LEN + EVP_GCM_TLS_FIXED_IV_LEN;

static int s2n_aead_cipher_aes_gcm_encrypt(struct s2n_session_key *key, struct s2n_blob *iv, struct s2n_blob *aad, struct s2n_blob *in, struct s2n_blob *out)
{
    gte_check(out->size, in->size);
    eq_check(iv->size, EVP_GCM_TLS_FIXED_IV_LEN + EVP_GCM_TLS_EXPLICIT_IV_LEN);
    eq_check(aad->size, 13);

    /* Initialize the IV */
    if (0 >= EVP_EncryptInit_ex(&key->native_format.evp_cipher_ctx, NULL, NULL, NULL, iv->data)) {
        S2N_ERROR(S2N_ERR_ENCRYPT);
    }

    /* Adjust our buffer pointers to account for the explicit IV and TAG lengths */
    int in_len = in->size - (EVP_GCM_TLS_EXPLICIT_IV_LEN + EVP_GCM_TLS_TAG_LEN);
    uint8_t *in_data = in->data + EVP_GCM_TLS_EXPLICIT_IV_LEN;
    uint8_t *out_data = out->data + EVP_GCM_TLS_EXPLICIT_IV_LEN;
    uint8_t *tag_data = out->data + out->size - EVP_GCM_TLS_TAG_LEN;

    int out_len;
    /* Specify the AAD */
    if (0 >= EVP_EncryptUpdate(&key->native_format.evp_cipher_ctx, NULL, &out_len, aad->data, aad->size)) {
        S2N_ERROR(S2N_ERR_ENCRYPT);
    }

    /* Encrypt the data */
    if (0 == EVP_EncryptUpdate(&key->native_format.evp_cipher_ctx, out_data, &out_len, in_data, in_len)) {
        S2N_ERROR(S2N_ERR_ENCRYPT);
    }

    /* Finalize */
    if (0 == EVP_EncryptFinal_ex(&key->native_format.evp_cipher_ctx, out_data, &out_len)) {
        S2N_ERROR(S2N_ERR_ENCRYPT);
    }

    /* write the tag */
    if (0 == EVP_CIPHER_CTX_ctrl(&key->native_format.evp_cipher_ctx, EVP_CTRL_GCM_GET_TAG, EVP_GCM_TLS_TAG_LEN, tag_data)) {
        S2N_ERROR(S2N_ERR_ENCRYPT);
    }

    return 0;
}

static int s2n_aead_cipher_aes_gcm_decrypt(struct s2n_session_key *key, struct s2n_blob *iv, struct s2n_blob *aad, struct s2n_blob *in, struct s2n_blob *out)
{
    gte_check(out->size, in->size);
    eq_check(iv->size, EVP_GCM_TLS_FIXED_IV_LEN + EVP_GCM_TLS_EXPLICIT_IV_LEN);
    eq_check(aad->size, 13);

    /* Initialize the IV */
    if (0 >= EVP_DecryptInit_ex(&key->native_format.evp_cipher_ctx, NULL, NULL, NULL, iv->data)) {
        S2N_ERROR(S2N_ERR_DECRYPT);
    }

    /* Adjust our buffer pointers to account for the explicit IV and TAG lengths */
    int in_len = in->size - (EVP_GCM_TLS_EXPLICIT_IV_LEN + EVP_GCM_TLS_TAG_LEN);
    uint8_t *in_data = in->data + EVP_GCM_TLS_EXPLICIT_IV_LEN;
    uint8_t *out_data = out->data + EVP_GCM_TLS_EXPLICIT_IV_LEN;
    uint8_t *tag_data = in->data + in->size - EVP_GCM_TLS_TAG_LEN;

    /* Set the TAG */
    if (0 == EVP_CIPHER_CTX_ctrl(&key->native_format.evp_cipher_ctx, EVP_CTRL_GCM_SET_TAG, EVP_GCM_TLS_TAG_LEN, tag_data)) {
        S2N_ERROR(S2N_ERR_DECRYPT);
    }

    int out_len;
    /* Specify the AAD */
    if (0 >= EVP_DecryptUpdate(&key->native_format.evp_cipher_ctx, NULL, &out_len, aad->data, aad->size)) {
        S2N_ERROR(S2N_ERR_DECRYPT);
    }

    /* Decrypt the data */
    if (0 == EVP_DecryptUpdate(&key->native_format.evp_cipher_ctx, out_data, &out_len, in_data, in_len)) {
        S2N_ERROR(S2N_ERR_DECRYPT);
    }

    /* Verify the tag */
    if (0 == EVP_DecryptFinal_ex(&key->native_format.evp_cipher_ctx, out_data, &out_len)) {
        S2N_ERROR(S2N_ERR_DECRYPT);
    }

    return 0;
}

static int s2n_aead_cipher_aes128_gcm_get_encryption_key(struct s2n_session_key *key, struct s2n_blob *in)
{
    eq_check(in->size, 16);

    EVP_EncryptInit_ex(&key->native_format.evp_cipher_ctx, EVP_aes_128_gcm(), NULL, NULL, NULL);
    EVP_CIPHER_CTX_ctrl(&key->native_format.evp_cipher_ctx, EVP_CTRL_GCM_SET_IVLEN, s2n_aes_gcm_iv_len, NULL);
    EVP_EncryptInit_ex(&key->native_format.evp_cipher_ctx, NULL, NULL, in->data, NULL);

    return 0;
}

static int s2n_aead_cipher_aes256_gcm_get_encryption_key(struct s2n_session_key *key, struct s2n_blob *in)
{
    eq_check(in->size, 32);

    EVP_EncryptInit_ex(&key->native_format.evp_cipher_ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
    EVP_CIPHER_CTX_ctrl(&key->native_format.evp_cipher_ctx, EVP_CTRL_GCM_SET_IVLEN, s2n_aes_gcm_iv_len, NULL);
    EVP_EncryptInit_ex(&key->native_format.evp_cipher_ctx, NULL, NULL, in->data, NULL);

    return 0;
}

static int s2n_aead_cipher_aes128_gcm_get_decryption_key(struct s2n_session_key *key, struct s2n_blob *in)
{
    eq_check(in->size, 16);

    EVP_DecryptInit_ex(&key->native_format.evp_cipher_ctx, EVP_aes_128_gcm(), NULL, NULL, NULL);
    EVP_CIPHER_CTX_ctrl(&key->native_format.evp_cipher_ctx, EVP_CTRL_GCM_SET_IVLEN, s2n_aes_gcm_iv_len, NULL);
    EVP_DecryptInit_ex(&key->native_format.evp_cipher_ctx, NULL, NULL, in->data, NULL);

    return 0;
}

static int s2n_aead_cipher_aes256_gcm_get_decryption_key(struct s2n_session_key *key, struct s2n_blob *in)
{
    eq_check(in->size, 32);

    EVP_DecryptInit_ex(&key->native_format.evp_cipher_ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
    EVP_CIPHER_CTX_ctrl(&key->native_format.evp_cipher_ctx, EVP_CTRL_GCM_SET_IVLEN, s2n_aes_gcm_iv_len, NULL);
    EVP_DecryptInit_ex(&key->native_format.evp_cipher_ctx, NULL, NULL, in->data, NULL);

    return 0;
}

struct s2n_cipher s2n_aes128_gcm = {
    .key_material_size = 16,
    .type = S2N_AEAD,
    .io.aead = {
                .record_iv_size = EVP_GCM_TLS_EXPLICIT_IV_LEN,
                .fixed_iv_size = EVP_GCM_TLS_FIXED_IV_LEN,
                .tag_size = EVP_GCM_TLS_TAG_LEN,
                .decrypt = s2n_aead_cipher_aes_gcm_decrypt,
                .encrypt = s2n_aead_cipher_aes_gcm_encrypt},
    .get_encryption_key = s2n_aead_cipher_aes128_gcm_get_encryption_key,
    .get_decryption_key = s2n_aead_cipher_aes128_gcm_get_decryption_key
};

struct s2n_cipher s2n_aes256_gcm = {
    .key_material_size = 32,
    .type = S2N_AEAD,
    .io.aead = {
                .record_iv_size = EVP_GCM_TLS_EXPLICIT_IV_LEN,
                .fixed_iv_size = EVP_GCM_TLS_FIXED_IV_LEN,
                .tag_size = EVP_GCM_TLS_TAG_LEN,
                .decrypt = s2n_aead_cipher_aes_gcm_decrypt,
                .encrypt = s2n_aead_cipher_aes_gcm_encrypt},
    .get_encryption_key = s2n_aead_cipher_aes256_gcm_get_encryption_key,
    .get_decryption_key = s2n_aead_cipher_aes256_gcm_get_decryption_key
};

