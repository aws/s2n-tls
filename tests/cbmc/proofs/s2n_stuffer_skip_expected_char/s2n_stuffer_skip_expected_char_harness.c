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

#include <assert.h>
#include <cbmc_proof/cbmc_utils.h>
#include <cbmc_proof/make_common_datastructures.h>

#include "api/s2n.h"
#include "stuffer/s2n_stuffer.h"

void s2n_stuffer_skip_expected_char_harness()
{
    /* Non-deterministic inputs. */
    struct s2n_stuffer *stuffer = cbmc_allocate_s2n_stuffer();
    const char expected;
    uint32_t   min;
    uint32_t   max;
    uint32_t   *skipped = malloc(sizeof(*skipped));

    /* Limit input size for bounded proofs. */
    __CPROVER_assume(S2N_IMPLIES(stuffer != NULL, s2n_blob_is_bounded(&stuffer->blob, MAX_BLOB_SIZE)));

    /* Save previous state from stuffer. */
    struct s2n_stuffer old_stuffer = {0};
    if (stuffer) old_stuffer = *stuffer;

    /* Operation under verification. */
    if (s2n_stuffer_skip_expected_char(stuffer, expected, min, max, skipped) == S2N_SUCCESS) {
        if (stuffer->blob.size > 0 && skipped) {
            /* Keep this check in the harness due to lack of quantifiers support in function contracts. */
            /* The skipped bytes should match the expected element. */
            uint32_t idx;
            __CPROVER_assume(idx >= old_stuffer.read_cursor && idx < (old_stuffer.read_cursor + *skipped));
            assert(stuffer->blob.data[ idx ] == expected);
        }
    }
}
