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

#include "tls/s2n_tls_parameters.h"

#include "crypto/s2n_hash.h"

/* Table to translate TLS numbers to s2n algorithms */
static const s2n_hash_algorithm s2n_hash_tls_to_alg[] = {
    [TLS_HASH_ALGORITHM_MD5] = S2N_HASH_MD5,
    [TLS_HASH_ALGORITHM_SHA1] = S2N_HASH_SHA1,
    [TLS_HASH_ALGORITHM_SHA224] = S2N_HASH_SHA224,
    [TLS_HASH_ALGORITHM_SHA256] = S2N_HASH_SHA256,
    [TLS_HASH_ALGORITHM_SHA384] = S2N_HASH_SHA384,
    [TLS_HASH_ALGORITHM_SHA512] = S2N_HASH_SHA512 };

/* Table to translate from s2n algorithm numbers to TLS numbers */
static const uint8_t s2n_hash_alg_to_tls[] = {
    [S2N_HASH_MD5] = TLS_HASH_ALGORITHM_MD5,
    [S2N_HASH_SHA1] = TLS_HASH_ALGORITHM_SHA1,
    [S2N_HASH_SHA224] = TLS_HASH_ALGORITHM_SHA224,
    [S2N_HASH_SHA256] = TLS_HASH_ALGORITHM_SHA256,
    [S2N_HASH_SHA384] = TLS_HASH_ALGORITHM_SHA384,
    [S2N_HASH_SHA512] = TLS_HASH_ALGORITHM_SHA512 };

