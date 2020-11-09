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
 * on an "AS IS" BASIS, WITHblock_size WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */

#include "api/s2n.h"
#include "crypto/s2n_hash.h"

#include <cbmc_proof/cbmc_utils.h>
#include <cbmc_proof/proof_allocators.h>

void s2n_hash_block_size_harness()
{
    /* Non-deterministic inputs. */
    s2n_hash_algorithm alg;
    size_t block_length;
    uint64_t *block_size = bounded_malloc(block_length);

    /* Operation under verification. */
    if(s2n_hash_block_size(alg, block_size) == S2N_SUCCESS)
    {
        /* Post-conditions. */
        assert(IMPLIES(alg == S2N_HASH_NONE, *block_size == 64));
        assert(IMPLIES(alg == S2N_HASH_MD5, *block_size == 64));
        assert(IMPLIES(alg == S2N_HASH_SHA1, *block_size == 64));
        assert(IMPLIES(alg == S2N_HASH_SHA224, *block_size == 64));
        assert(IMPLIES(alg == S2N_HASH_SHA256, *block_size == 64));
        assert(IMPLIES(alg == S2N_HASH_SHA384, *block_size == 128));
        assert(IMPLIES(alg == S2N_HASH_SHA512, *block_size == 128));
        assert(IMPLIES(alg == S2N_HASH_MD5_SHA1, *block_size == 64));
    }
}
