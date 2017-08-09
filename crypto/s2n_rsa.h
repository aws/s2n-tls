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

#include <stdint.h>

#include <openssl/rsa.h>

#include "crypto/s2n_hash.h"

#include "utils/s2n_blob.h"

struct s2n_pkey;

struct s2n_rsa_key {
    RSA *rsa;
};

extern int s2n_rsa_pkey_init(struct s2n_pkey *pkey);

extern int s2n_rsa_sign(const struct s2n_pkey *key, struct s2n_hash_state *digest, struct s2n_blob *signature);
extern int s2n_rsa_verify(const struct s2n_pkey *key, struct s2n_hash_state *digest, struct s2n_blob *signature);
extern int s2n_rsa_encrypt(const struct s2n_pkey *key, struct s2n_blob *in, struct s2n_blob *out);
extern int s2n_rsa_decrypt(const struct s2n_pkey *key, struct s2n_blob *in, struct s2n_blob *out);
extern int s2n_rsa_keys_match(const struct s2n_pkey *pub, const struct s2n_pkey *priv);
extern int s2n_rsa_key_free(struct s2n_pkey *pkey);

extern int s2n_rsa_public_encrypted_size(const s2n_rsa_public_key *key);
extern int s2n_rsa_private_encrypted_size(const s2n_rsa_private_key *key);

extern int s2n_rsa_check_key(const struct s2n_pkey *pkey);

extern int s2n_pkey_to_rsa_public_key(s2n_rsa_public_key *rsa_key, EVP_PKEY *pkey);
extern int s2n_pkey_to_rsa_private_key(s2n_rsa_private_key *rsa_key, EVP_PKEY *pkey);
