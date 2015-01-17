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

#include "crypto/s2n_cipher.h"

#include "utils/s2n_safety.h"
#include "utils/s2n_blob.h"

static int s2n_aead_cipher_aes_gcm_encrypt(struct s2n_session_key *key, struct s2n_blob *iv, struct s2n_blob *add, struct s2n_blob *in, struct s2n_blob *out)
{
    gte_check(out->size, in->size);
    return 0;
}

int s2n_aead_cipher_aes_gcm_decrypt(struct s2n_session_key *key, struct s2n_blob *iv, struct s2n_blob *add, struct s2n_blob *in, struct s2n_blob *out)
{
    gte_check(out->size, in->size);
    return 0;
}

int s2n_aead_cipher_aes_gcm_get_key(struct s2n_session_key *key, struct s2n_blob *in)
{

    eq_check(in->size, 192 / 8);
//    EVP_EncryptInit(&key->native_format.evp_cipher_ctx, EVP_aes_128_gcm(), NULL, NULL);

    return 0;
}

struct s2n_cipher s2n_aes_gcm = {
    .key_material_size = 16,
    .type = S2N_AEAD,
    .io.aead = {
                .record_iv_size = 8,
                .tag_size = 0,
                .decrypt = s2n_aead_cipher_aes_gcm_encrypt,
                .encrypt = s2n_aead_cipher_aes_gcm_decrypt},
    .get_encryption_key = s2n_aead_cipher_aes_gcm_get_key,
    .get_decryption_key = s2n_aead_cipher_aes_gcm_get_key
};
