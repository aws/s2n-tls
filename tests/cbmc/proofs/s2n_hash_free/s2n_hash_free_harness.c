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

#include "crypto/s2n_fips.h"
#include "crypto/s2n_hash.h"

#include <cbmc_proof/make_common_datastructures.h>

#include <assert.h>

void s2n_hash_free_harness()
{
    /* Non-deterministic inputs. */
    struct s2n_hash_state *state = cbmc_allocate_s2n_hash_state();

    /* Assumptions. */
    __CPROVER_assume(s2n_result_is_ok(s2n_hash_state_validate(state)));

    struct rc_keys_from_hash_state saved_hash_state;
    save_rc_keys_from_hash_state(state, &saved_hash_state);

    /* Operation under verification. */
    assert(s2n_hash_free(state) == S2N_SUCCESS);
    if (state != NULL) {
        assert(state->hash_impl->free != NULL);
        if (s2n_is_in_fips_mode()) {
            assert(state->digest.high_level.evp.ctx == NULL);
            assert(state->digest.high_level.evp_md5_secondary.ctx == NULL);
            assert_rc_decrement_on_hash_state(&saved_hash_state);
        } else {
            assert_rc_unchanged_on_hash_state(&saved_hash_state);
        }
        assert(state->is_ready_for_input == 0);
    }

    /* Cleanup after expected error cases, for memory leak check. */
    if (state != NULL) {
        /* 1. `free` leftover EVP_MD_CTX objects if `s2n_is_in_fips_mode`,
              since `s2n_hash_free` is a NO-OP in that case. */
        if (!s2n_is_in_fips_mode()) {
            S2N_EVP_MD_CTX_FREE(state->digest.high_level.evp.ctx);
            S2N_EVP_MD_CTX_FREE(state->digest.high_level.evp_md5_secondary.ctx);
        }

        /* 2. `free` leftover reference-counted keys (i.e. those with non-zero ref-count),
              since they are not automatically `free`d until their ref count reaches 0. */
        free_rc_keys_from_hash_state(&saved_hash_state);
    }
    /* 3. free our heap-allocated `state` since `s2n_hash_free` only `free`s the contents. */
    free(state);
}
