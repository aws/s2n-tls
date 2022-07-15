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

#include "crypto/s2n_hash.h"

#include <cbmc_proof/make_common_datastructures.h>

#include <assert.h>

int __CPROVER_file_local_s2n_hash_c_s2n_hash_set_impl(struct s2n_hash_state *);

void s2n_hash_const_time_get_currently_in_hash_block_harness()
{
    /* Non-deterministic inputs. */
    struct s2n_hash_state *state = cbmc_allocate_s2n_hash_state();
    uint64_t* out = malloc(sizeof(*out));

    /* Assumptions. */
    __CPROVER_assume(s2n_result_is_ok(s2n_hash_state_validate(state)));
    if (state != NULL)
    {
        __CPROVER_file_local_s2n_hash_c_s2n_hash_set_impl(state);
    }

    /* Operation under verification. */
    if (s2n_hash_const_time_get_currently_in_hash_block(state, out) == S2N_SUCCESS)
    {
        /* Post-conditions. */
        assert(s2n_result_is_ok(s2n_hash_state_validate(state)));
        assert(state->is_ready_for_input);
        uint64_t hash_block_size = 0;
        s2n_hash_block_size(state->alg, &hash_block_size);
        /* Checks whether hash_block_size is power of two. */
        assert(hash_block_size && (!(hash_block_size & (hash_block_size - 1))));
    }
}
