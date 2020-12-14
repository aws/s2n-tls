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
#include <cbmc_proof/proof_allocators.h>

void s2n_hash_reset_harness()
{
    /* Non-deterministic inputs. */
    struct s2n_hash_state *state = cbmc_allocate_s2n_hash_state();

    /* Operation under verification. */
    if (s2n_hash_reset(state) == S2N_SUCCESS)
    {
        /* Post-conditions. */
        assert(s2n_result_is_ok(s2n_hash_state_validate(state)));
        assert(state->hash_impl->reset != NULL);
    }
}
