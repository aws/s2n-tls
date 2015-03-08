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

#include "utils/s2n_blob.h"

/* We reseed after 2^48 bytes have been generated */
#define S2N_DRBG_RESEED_LIMIT   281474976710656

struct s2n_drbg {
    int initialized:1;
    uint64_t bytes_used;
    uint8_t cache[128];
    uint8_t cache_remaining;
    EVP_CIPHER_CTX evp_cipher_ctx;
    uint32_t generation;
};

extern int s2n_drbg_seed(struct s2n_drbg *drbg);
extern int s2n_drbg_generate(struct s2n_drbg *drbg, struct s2n_blob *blob);
