/*
 * Copyright 2016 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

#include "tls/s2n_tls_parameters.h"

#include "crypto/s2n_hash.h"

#include "utils/s2n_blob.h"

extern const s2n_hash_algorithm s2n_hash_tls_to_alg[];
extern const uint8_t s2n_hash_alg_to_tls[];

struct s2n_digest_hash_preferences {
    uint8_t all_preferences[5];
    uint8_t fips_preferences[4];
};

extern struct s2n_digest_hash_preferences s2n_digest_hashes;

/* Set during s2n_fips_init to either s2n_digest_hashes.all_preferences or s2n_digest_hashes.fips_preferences. */
extern struct s2n_blob s2n_preferred_hashes;
