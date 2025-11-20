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

#include <cbmc_proof/cbmc_utils.h>

#include "crypto/s2n_hash.h"

#include <assert.h>

void s2n_hash_digest_size_harness()
{
    /* Non-deterministic inputs. */
    s2n_hash_algorithm alg;
    uint8_t *          out = malloc(sizeof(*out));

    /* Operation under verification. */
    if (s2n_hash_digest_size(alg, out) == S2N_SUCCESS) {
        assert(*out <= S2N_MAX_DIGEST_LEN);
    }
}
