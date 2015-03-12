/*
 * Copyright 2015 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

#include "crypto/s2n_hash.h"
#include "utils/s2n_blob.h"

/* We reseed after 2^35 bytes have been generated: from NIST SP800-90A 10.2.1 Table 3 */
#define S2N_DRBG_RESEED_LIMIT   34359738368

/* The maximum size of any one request: from NIST SP800-90A 10.2.1 Table 3 */
#define S2N_DRBG_GENERATE_LIMIT 8192

struct s2n_drbg {
    struct s2n_blob value;
    uint8_t key[16];
    uint8_t v[16];
    uint64_t bytes_used;
    uint32_t generation;

    /* Function pointer to the entropy generating function. If it's NULL, then
     * s2n_get_urandom_data() will be used. This function pointer is intended
     * ONLY for the s2n_drbg_test case to use, so that known entropy data can
     * fed to the DRBG test vectors.
     */
    int (*entropy_generator)(struct s2n_blob *);
};

/* Per NIST SP 800-90C 6.3
 *
 * s2n's DRBG does not provide prediction resistance (the internal state must be kept secret),
 * and does not support the additional_input parameter (which per 800-90C may be zero).
 *
  * The security strength provided by s2n's DRBG is fixed in size (128 bits).
 */
extern int s2n_drbg_instantiate(struct s2n_drbg *drbg, struct s2n_blob *personalization_string);
extern int s2n_drbg_generate(struct s2n_drbg *drbg, struct s2n_blob *returned_bits);
