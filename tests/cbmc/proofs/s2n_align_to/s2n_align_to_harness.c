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
#include <cbmc_proof/make_common_datastructures.h>
#include <cbmc_proof/proof_allocators.h>

#include "api/s2n.h"
#include "utils/s2n_safety.h"

int s2n_align_to_harness()
{
    const uint32_t initial;
    const uint32_t alignment;
    /* Division and modulo are too slow in CBMC to perform all necessary checks,
     * so relevant assertions that can't be used currently have been left in comments. */
    uint32_t *out = can_fail_malloc(sizeof(uint32_t));
    /* uint64_t result = (uint64_t) alignment * ((((uint64_t) initial - 1) / (uint64_t) alignment) + 1); */

    if (s2n_align_to(initial, alignment, out) == S2N_SUCCESS) {
        if (initial == 0) {
            assert(*out == 0);
        } else {
            /* assert(*out >= initial); */
            /* assert(*out < (uint64_t) initial + (uint64_t) alignment); */
            /* assert(result <= UINT32_MAX); */
            /* assert(*out % alignment == 0); */
        }
    } else {
        /* assert(*out % alignment != 0 || out == NULL); */
        /* assert(result > UINT32_MAX || out == NULL); */
    }
}
