/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"). You may not use
 * this file except in compliance with the License. A copy of the License is
 * located at
 *
 *     http://aws.amazon.com/apache2.0/
 *
 * or in the "license" file accompanying this file. This file is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 * implied. See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <cbmc_proof/nondet.h>

#include "api/s2n.h"
#include "crypto/s2n_hash.h"
#include "utils/s2n_safety.h"

int s2n_hash_digest(struct s2n_hash_state *state, void *out, uint32_t size)
{
    POSIX_PRECONDITION(s2n_hash_state_validate(state));
    POSIX_ENSURE(S2N_MEM_IS_READABLE(out, size), S2N_ERR_PRECONDITION_VIOLATION);
    POSIX_ENSURE_REF(state->hash_impl->digest);

    /* return state->hash_impl->digest(state, out, size); */
    return nondet_bool() ? S2N_SUCCESS : S2N_FAILURE;
}
