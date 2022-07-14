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

#include <cbmc_proof/make_common_datastructures.h>

#include "crypto/s2n_hmac.h"

#include <assert.h>

void s2n_hmac_restore_evp_hash_state_harness()
{
    /* Non-deterministic inputs. */
    struct s2n_hmac_state *state = cbmc_allocate_s2n_hmac_state();
    struct s2n_hmac_evp_backup *backup = cbmc_allocate_s2n_hmac_evp_backup();

    /* Operation under verification. */
    if (s2n_hmac_restore_evp_hash_state(backup, state) == S2N_SUCCESS) {
        /* Postconditions. */
        assert(s2n_result_is_ok(s2n_hmac_state_validate(state)));
        assert(state->inner.digest.high_level == backup->inner);
        assert(state->inner_just_key.digest.high_level == backup->inner_just_key);
        assert(state->outer.digest.high_level == backup->outer);
        assert(state->outer_just_key.digest.high_level == backup->outer_just_key);
    }
}
