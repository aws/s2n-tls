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

#include "crypto/s2n_hmac.h"

#include <cbmc_proof/make_common_datastructures.h>

#include <assert.h>

int __CPROVER_file_local_s2n_hash_c_s2n_hash_set_impl(struct s2n_hash_state *);

void s2n_hmac_digest_two_compression_rounds_harness()
{
    /* Non-deterministic inputs. */
    struct s2n_hmac_state *state = cbmc_allocate_s2n_hmac_state();
    uint32_t size;
    void* out = malloc(size);

    /* Assumptions. */
    __CPROVER_assume(s2n_result_is_ok(s2n_hmac_state_validate(state)));
    __CPROVER_file_local_s2n_hash_c_s2n_hash_set_impl(&state->inner);
    __CPROVER_file_local_s2n_hash_c_s2n_hash_set_impl(&state->outer);
    __CPROVER_file_local_s2n_hash_c_s2n_hash_set_impl(&state->outer_just_key);

    /* Operation under verification. */
    if (s2n_hmac_digest_two_compression_rounds(state, out, size) == S2N_SUCCESS)
    {
        /* Post-conditions. */
        assert(s2n_result_is_ok(s2n_hmac_state_validate(state)));
        assert(state->inner.hash_impl->digest != NULL);
        assert(state->outer.hash_impl->digest != NULL);
        assert(state->outer.hash_impl->update != NULL);
        assert(state->outer_just_key.hash_impl->copy != NULL);
    }
}
