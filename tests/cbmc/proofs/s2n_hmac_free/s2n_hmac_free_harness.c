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

void s2n_hmac_free_harness()
{
    /* Non-deterministic inputs. */
    struct s2n_hmac_state *state = cbmc_allocate_s2n_hmac_state();

    /* Operation under verification. */
    if (s2n_hmac_free(state) == S2N_SUCCESS)
    {
        /* Post-conditions. */
        if (state != NULL) {
            assert(state->inner.hash_impl->free != NULL);
            assert(IMPLIES(s2n_is_in_fips_mode(), state->inner.digest.high_level.evp.ctx == NULL));
            assert(IMPLIES(s2n_is_in_fips_mode(), state->inner.digest.high_level.evp_md5_secondary.ctx == NULL));
            assert(state->inner.is_ready_for_input == 0);
            assert(state->inner_just_key.hash_impl->free != NULL);
            assert(IMPLIES(s2n_is_in_fips_mode(), state->inner_just_key.digest.high_level.evp.ctx == NULL));
            assert(IMPLIES(s2n_is_in_fips_mode(), state->inner_just_key.digest.high_level.evp_md5_secondary.ctx == NULL));
            assert(state->inner_just_key.is_ready_for_input == 0);
            assert(state->outer.hash_impl->free != NULL);
            assert(IMPLIES(s2n_is_in_fips_mode(), state->outer.digest.high_level.evp.ctx == NULL));
            assert(IMPLIES(s2n_is_in_fips_mode(), state->outer.digest.high_level.evp_md5_secondary.ctx == NULL));
            assert(state->outer.is_ready_for_input == 0);
            assert(state->outer_just_key.hash_impl->free != NULL);
            assert(IMPLIES(s2n_is_in_fips_mode(), state->outer_just_key.digest.high_level.evp.ctx == NULL));
            assert(IMPLIES(s2n_is_in_fips_mode(), state->outer_just_key.digest.high_level.evp_md5_secondary.ctx == NULL));
            assert(state->outer_just_key.is_ready_for_input == 0);
        }
    }
}
