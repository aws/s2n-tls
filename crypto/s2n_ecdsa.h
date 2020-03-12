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

#pragma once

#include <openssl/ecdsa.h>
#include <stdint.h>
#include <s2n.h>

#include "stuffer/s2n_stuffer.h"

#include "crypto/s2n_ecc_evp.h"
#include "crypto/s2n_hash.h"

#include "utils/s2n_blob.h"

/* Forward declaration to avoid the circular dependency with s2n_pkey.h */
struct s2n_pkey;

struct s2n_ecdsa_key {
    EC_KEY *ec_key;
};

typedef struct s2n_ecdsa_key s2n_ecdsa_public_key;
typedef struct s2n_ecdsa_key s2n_ecdsa_private_key;

extern int s2n_ecdsa_pkey_init(struct s2n_pkey *pkey);
extern int s2n_ecdsa_pkey_matches_curve(const struct s2n_ecdsa_key *ecdsa_key, const struct s2n_ecc_named_curve *curve);

extern int s2n_evp_pkey_to_ecdsa_public_key(s2n_ecdsa_public_key *ecdsa_key, EVP_PKEY *pkey);
extern int s2n_evp_pkey_to_ecdsa_private_key(s2n_ecdsa_private_key *ecdsa_key, EVP_PKEY *pkey);
