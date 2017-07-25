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

#pragma once

#include <openssl/ecdsa.h>
#include <stdint.h>

#include "stuffer/s2n_stuffer.h"

#include "crypto/s2n_hash.h"

#include "utils/s2n_blob.h"

struct s2n_ecdsa_public_key {
    EC_KEY *eckey;
};

struct s2n_ecdsa_private_key {
    EC_KEY *eckey;
};

extern int s2n_asn1der_to_ecdsa_public_key(struct s2n_ecdsa_public_key *key, struct s2n_blob *asn1der);
extern int s2n_asn1der_to_ecdsa_private_key(struct s2n_ecdsa_private_key *key, struct s2n_blob *asn1der);
extern int s2n_ecdsa_public_key_free(struct s2n_ecdsa_public_key *key);
extern int s2n_ecdsa_private_key_free(struct s2n_ecdsa_private_key *key);

extern int s2n_ecdsa_sign(const struct s2n_ecdsa_private_key *key, struct s2n_hash_state *digest, struct s2n_blob *signature);
extern int s2n_ecdsa_verify(const struct s2n_ecdsa_public_key *key, struct s2n_hash_state *digest, struct s2n_blob *signature);

extern int s2n_ecdsa_signature_size(const struct s2n_ecdsa_private_key *key);

extern int s2n_ecdsa_keys_match(const struct s2n_ecdsa_public_key *pub_key, const struct s2n_ecdsa_private_key *priv_key);
