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

void s2n_hmac_init_harness()
{
    /* Non-deterministic inputs. */
    struct s2n_hmac_state *state = cbmc_allocate_s2n_hmac_state();
    s2n_hmac_algorithm alg;
    uint32_t klen;
    uint8_t *key = malloc(klen);

    /* Operation under verification. */
    if (s2n_hmac_init(state, alg, key, klen) == S2N_SUCCESS) {
        /* Post-conditions. */
        assert(s2n_result_is_ok(s2n_hmac_state_validate(state)));
        assert(S2N_MEM_IS_READABLE(key, klen));
    }
}
