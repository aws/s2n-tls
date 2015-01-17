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

#include <openssl/rsa.h>
#include <stdint.h>

#include "stuffer/s2n_stuffer.h"

#include "crypto/s2n_hash.h"

#include "utils/s2n_blob.h"

struct s2n_rsa_public_key {
    RSA *rsa;
};

struct s2n_rsa_private_key {
    RSA *rsa;
};

extern int s2n_rsa_keys_match(struct s2n_rsa_public_key *pub, struct s2n_rsa_private_key *priv);
extern int s2n_asn1der_to_rsa_public_key(struct s2n_rsa_public_key *key, struct s2n_blob *asn1der);
extern int s2n_asn1der_to_rsa_private_key(struct s2n_rsa_private_key *key, struct s2n_blob *asn1der);
extern int s2n_rsa_encrypt(struct s2n_rsa_public_key *key, struct s2n_blob *in, struct s2n_blob *out);
extern int s2n_rsa_decrypt(struct s2n_rsa_private_key *key, struct s2n_blob *in, struct s2n_blob *out);
extern int s2n_rsa_public_key_free(struct s2n_rsa_public_key *key);
extern int s2n_rsa_private_key_free(struct s2n_rsa_private_key *key);
extern int s2n_rsa_public_encrypted_size(struct s2n_rsa_public_key *key);
extern int s2n_rsa_private_encrypted_size(struct s2n_rsa_private_key *key);
extern int s2n_rsa_sign(struct s2n_rsa_private_key *key, struct s2n_hash_state *digest, struct s2n_blob *signature);
extern int s2n_rsa_verify(struct s2n_rsa_public_key *key, struct s2n_hash_state *digest, struct s2n_blob *signature);
