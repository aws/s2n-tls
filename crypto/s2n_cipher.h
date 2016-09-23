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

#pragma once

#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/rc4.h>
#include <openssl/des.h>
#include <openssl/rsa.h>
#include <openssl/dh.h>

#include "crypto/s2n_crypto.h"

#include "utils/s2n_blob.h"

struct s2n_session_key {
    EVP_CIPHER_CTX *evp_cipher_ctx;
};

struct s2n_stream_cipher {
    int (*decrypt) (struct s2n_session_key * key, struct s2n_blob * in, struct s2n_blob * out);
    int (*encrypt) (struct s2n_session_key * key, struct s2n_blob * in, struct s2n_blob * out);
};

struct s2n_cbc_cipher {
    uint8_t block_size;
    uint8_t record_iv_size;
    int (*decrypt) (struct s2n_session_key * key, struct s2n_blob * iv, struct s2n_blob * in, struct s2n_blob * out);
    int (*encrypt) (struct s2n_session_key * key, struct s2n_blob * iv, struct s2n_blob * in, struct s2n_blob * out);
};

struct s2n_aead_cipher {
    uint8_t fixed_iv_size;
    uint8_t record_iv_size;
    uint8_t tag_size;
    int (*decrypt) (struct s2n_session_key * key, struct s2n_blob * iv, struct s2n_blob * add, struct s2n_blob * in, struct s2n_blob * out);
    int (*encrypt) (struct s2n_session_key * key, struct s2n_blob * iv, struct s2n_blob * add, struct s2n_blob * in, struct s2n_blob * out);
};

struct s2n_cipher {
    enum { S2N_STREAM, S2N_CBC, S2N_AEAD } type;
    union {
        struct s2n_stream_cipher stream;
        struct s2n_aead_cipher aead;
        struct s2n_cbc_cipher cbc;
    } io;
    uint8_t key_material_size;
    int (*init) (struct s2n_session_key * key);
    int (*get_decryption_key) (struct s2n_session_key * key, struct s2n_blob * in);
    int (*get_encryption_key) (struct s2n_session_key * key, struct s2n_blob * in);
    int (*destroy_key) (struct s2n_session_key * key);
};

extern int s2n_session_key_alloc(struct s2n_session_key *key);
extern int s2n_session_key_free(struct s2n_session_key *key);

extern struct s2n_cipher s2n_null_cipher;
extern struct s2n_cipher s2n_rc4;
extern struct s2n_cipher s2n_aes128;
extern struct s2n_cipher s2n_aes256;
extern struct s2n_cipher s2n_3des;
extern struct s2n_cipher s2n_aes128_gcm;
extern struct s2n_cipher s2n_aes256_gcm;
