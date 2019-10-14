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

#include "tls/s2n_crypto.h"

#include "utils/s2n_safety.h"
#include "utils/s2n_blob.h"

static uint8_t s2n_aead_cipher_aes128_gcm_available()
{
    return (EVP_aes_128_gcm() ? 1 : 0);
}

static uint8_t s2n_aead_cipher_aes256_gcm_available()
{
    return (EVP_aes_256_gcm() ? 1 : 0);
}

static int s2n_aead_cipher_aes_gcm_encrypt(struct s2n_session_key *key, struct s2n_blob *iv, struct s2n_blob *aad, struct s2n_blob *in, struct s2n_blob *out)
{
    gte_check(in->size, S2N_TLS_GCM_TAG_LEN);
    gte_check(out->size, in->size);
    eq_check(iv->size, S2N_TLS_GCM_IV_LEN);

    /* Initialize the IV */
    GUARD_OSSL(EVP_EncryptInit_ex(key->evp_cipher_ctx, NULL, NULL, NULL, iv->data), S2N_ERR_KEY_INIT);

    /* Adjust our buffer pointers to account for the explicit IV and TAG lengths */
    int in_len = in->size - S2N_TLS_GCM_TAG_LEN;
    uint8_t *tag_data = out->data + out->size - S2N_TLS_GCM_TAG_LEN;

    int out_len;
    /* Specify the AAD */
    GUARD_OSSL(EVP_EncryptUpdate(key->evp_cipher_ctx, NULL, &out_len, aad->data, aad->size), S2N_ERR_ENCRYPT);

    /* Encrypt the data */
    GUARD_OSSL(EVP_EncryptUpdate(key->evp_cipher_ctx, out->data, &out_len, in->data, in_len), S2N_ERR_ENCRYPT);

    /* Finalize */
    GUARD_OSSL(EVP_EncryptFinal_ex(key->evp_cipher_ctx, out->data, &out_len), S2N_ERR_ENCRYPT);

    /* write the tag */
    GUARD_OSSL(EVP_CIPHER_CTX_ctrl(key->evp_cipher_ctx, EVP_CTRL_GCM_GET_TAG, S2N_TLS_GCM_TAG_LEN, tag_data), S2N_ERR_ENCRYPT);

    return 0;
}

static int s2n_aead_cipher_aes_gcm_decrypt(struct s2n_session_key *key, struct s2n_blob *iv, struct s2n_blob *aad, struct s2n_blob *in, struct s2n_blob *out)
{
    gte_check(in->size, S2N_TLS_GCM_TAG_LEN);
    gte_check(out->size, in->size);
    eq_check(iv->size, S2N_TLS_GCM_IV_LEN);

    /* Initialize the IV */
    GUARD_OSSL(EVP_DecryptInit_ex(key->evp_cipher_ctx, NULL, NULL, NULL, iv->data), S2N_ERR_KEY_INIT);

    /* Adjust our buffer pointers to account for the explicit IV and TAG lengths */
    int in_len = in->size - S2N_TLS_GCM_TAG_LEN;
    uint8_t *tag_data = in->data + in->size - S2N_TLS_GCM_TAG_LEN;

    /* Set the TAG */
    GUARD_OSSL(EVP_CIPHER_CTX_ctrl(key->evp_cipher_ctx, EVP_CTRL_GCM_SET_TAG, S2N_TLS_GCM_TAG_LEN, tag_data), S2N_ERR_DECRYPT);

    int out_len;
    /* Specify the AAD */
    GUARD_OSSL(EVP_DecryptUpdate(key->evp_cipher_ctx, NULL, &out_len, aad->data, aad->size), S2N_ERR_DECRYPT);

    int evp_decrypt_rc = 1;
    /* Decrypt the data, but don't short circuit tag verification. EVP_Decrypt* return 0 on failure, 1 for success. */
    evp_decrypt_rc &= EVP_DecryptUpdate(key->evp_cipher_ctx, out->data, &out_len, in->data, in_len);

    /* Verify the tag */
    evp_decrypt_rc &= EVP_DecryptFinal_ex(key->evp_cipher_ctx, out->data, &out_len);

    S2N_ERROR_IF(evp_decrypt_rc != 1, S2N_ERR_DECRYPT);

    return 0;
}

static int s2n_aead_cipher_aes128_gcm_set_encryption_key(struct s2n_session_key *key, struct s2n_blob *in)
{
    eq_check(in->size, 16);

    GUARD_OSSL(EVP_EncryptInit_ex(key->evp_cipher_ctx, EVP_aes_128_gcm(), NULL, NULL, NULL), S2N_ERR_KEY_INIT);

    EVP_CIPHER_CTX_ctrl(key->evp_cipher_ctx, EVP_CTRL_GCM_SET_IVLEN, S2N_TLS_GCM_IV_LEN, NULL);

    GUARD_OSSL(EVP_EncryptInit_ex(key->evp_cipher_ctx, NULL, NULL, in->data, NULL), S2N_ERR_KEY_INIT);

    return 0;
}

static int s2n_aead_cipher_aes256_gcm_set_encryption_key(struct s2n_session_key *key, struct s2n_blob *in)
{
    eq_check(in->size, 32);

    GUARD_OSSL(EVP_EncryptInit_ex(key->evp_cipher_ctx, EVP_aes_256_gcm(), NULL, NULL, NULL), S2N_ERR_KEY_INIT);

    EVP_CIPHER_CTX_ctrl(key->evp_cipher_ctx, EVP_CTRL_GCM_SET_IVLEN, S2N_TLS_GCM_IV_LEN, NULL);

    GUARD_OSSL(EVP_EncryptInit_ex(key->evp_cipher_ctx, NULL, NULL, in->data, NULL), S2N_ERR_KEY_INIT);

    return 0;
}

static int s2n_aead_cipher_aes128_gcm_set_decryption_key(struct s2n_session_key *key, struct s2n_blob *in)
{
    eq_check(in->size, 16);

    GUARD_OSSL(EVP_DecryptInit_ex(key->evp_cipher_ctx, EVP_aes_128_gcm(), NULL, NULL, NULL), S2N_ERR_KEY_INIT);

    EVP_CIPHER_CTX_ctrl(key->evp_cipher_ctx, EVP_CTRL_GCM_SET_IVLEN, S2N_TLS_GCM_IV_LEN, NULL);

    GUARD_OSSL(EVP_DecryptInit_ex(key->evp_cipher_ctx, NULL, NULL, in->data, NULL), S2N_ERR_KEY_INIT);

    return 0;
}

static int s2n_aead_cipher_aes256_gcm_set_decryption_key(struct s2n_session_key *key, struct s2n_blob *in)
{
    eq_check(in->size, 32);

    GUARD_OSSL(EVP_DecryptInit_ex(key->evp_cipher_ctx, EVP_aes_256_gcm(), NULL, NULL, NULL), S2N_ERR_KEY_INIT);

    EVP_CIPHER_CTX_ctrl(key->evp_cipher_ctx, EVP_CTRL_GCM_SET_IVLEN, S2N_TLS_GCM_IV_LEN, NULL);

    GUARD_OSSL(EVP_DecryptInit_ex(key->evp_cipher_ctx, NULL, NULL, in->data, NULL), S2N_ERR_KEY_INIT);

    return 0;
}

static int s2n_aead_cipher_aes_gcm_init(struct s2n_session_key *key)
{
    s2n_evp_ctx_init(key->evp_cipher_ctx);

    return 0;
}

static int s2n_aead_cipher_aes_gcm_destroy_key(struct s2n_session_key *key)
{
    EVP_CIPHER_CTX_cleanup(key->evp_cipher_ctx);

    return 0;
}

struct s2n_cipher s2n_aes128_gcm = {
    .key_material_size = 16,
    .type = S2N_AEAD,
    .io.aead = {
                .record_iv_size = S2N_TLS_GCM_EXPLICIT_IV_LEN,
                .fixed_iv_size = S2N_TLS_GCM_FIXED_IV_LEN,
                .tag_size = S2N_TLS_GCM_TAG_LEN,
                .decrypt = s2n_aead_cipher_aes_gcm_decrypt,
                .encrypt = s2n_aead_cipher_aes_gcm_encrypt},
    .is_available = s2n_aead_cipher_aes128_gcm_available,
    .init = s2n_aead_cipher_aes_gcm_init,
    .set_encryption_key = s2n_aead_cipher_aes128_gcm_set_encryption_key,
    .set_decryption_key = s2n_aead_cipher_aes128_gcm_set_decryption_key,
    .destroy_key = s2n_aead_cipher_aes_gcm_destroy_key,
};

struct s2n_cipher s2n_aes256_gcm = {
    .key_material_size = 32,
    .type = S2N_AEAD,
    .io.aead = {
                .record_iv_size = S2N_TLS_GCM_EXPLICIT_IV_LEN,
                .fixed_iv_size = S2N_TLS_GCM_FIXED_IV_LEN,
                .tag_size = S2N_TLS_GCM_TAG_LEN,
                .decrypt = s2n_aead_cipher_aes_gcm_decrypt,
                .encrypt = s2n_aead_cipher_aes_gcm_encrypt},
    .is_available = s2n_aead_cipher_aes256_gcm_available,
    .init = s2n_aead_cipher_aes_gcm_init,
    .set_encryption_key = s2n_aead_cipher_aes256_gcm_set_encryption_key,
    .set_decryption_key = s2n_aead_cipher_aes256_gcm_set_decryption_key,
    .destroy_key = s2n_aead_cipher_aes_gcm_destroy_key,
};

/* TLS 1.3 GCM ciphers */
struct s2n_cipher s2n_tls13_aes128_gcm = {
    .key_material_size = 16,
    .type = S2N_AEAD,
    .io.aead = {
                .record_iv_size = S2N_TLS13_RECORD_IV_LEN,
                .fixed_iv_size = S2N_TLS13_FIXED_IV_LEN,
                .tag_size = S2N_TLS_GCM_TAG_LEN,
                .decrypt = s2n_aead_cipher_aes_gcm_decrypt,
                .encrypt = s2n_aead_cipher_aes_gcm_encrypt},
    .is_available = s2n_aead_cipher_aes128_gcm_available,
    .init = s2n_aead_cipher_aes_gcm_init,
    .set_encryption_key = s2n_aead_cipher_aes128_gcm_set_encryption_key,
    .set_decryption_key = s2n_aead_cipher_aes128_gcm_set_decryption_key,
    .destroy_key = s2n_aead_cipher_aes_gcm_destroy_key,
};

struct s2n_cipher s2n_tls13_aes256_gcm = {
    .key_material_size = 32,
    .type = S2N_AEAD,
    .io.aead = {
                .record_iv_size = S2N_TLS13_RECORD_IV_LEN,
                .fixed_iv_size = S2N_TLS13_FIXED_IV_LEN,
                .tag_size = S2N_TLS_GCM_TAG_LEN,
                .decrypt = s2n_aead_cipher_aes_gcm_decrypt,
                .encrypt = s2n_aead_cipher_aes_gcm_encrypt},
    .is_available = s2n_aead_cipher_aes256_gcm_available,
    .init = s2n_aead_cipher_aes_gcm_init,
    .set_encryption_key = s2n_aead_cipher_aes256_gcm_set_encryption_key,
    .set_decryption_key = s2n_aead_cipher_aes256_gcm_set_decryption_key,
    .destroy_key = s2n_aead_cipher_aes_gcm_destroy_key,
};
