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
#include <cbmc_proof/proof_allocators.h>
#include <sys/param.h>

#include "api/s2n.h"
#include "utils/s2n_safety.h"

void s2n_constant_time_equals_harness()
{
    /* Non-deterministic inputs. */
    uint32_t len;
    uint32_t alen;
    uint32_t blen;
    __CPROVER_assume(len < MAX_ARR_LEN);
    __CPROVER_assume(alen >= len);
    __CPROVER_assume(blen >= len);
    uint8_t *a = can_fail_malloc(alen);
    uint8_t *b = can_fail_malloc(blen);

    /* Pre-conditions. */
    __CPROVER_assume(S2N_IMPLIES(len != 0, a != NULL && b != NULL));

    /* Check logical equivalence of s2n_constant_time_equals against element equality */
    if (s2n_constant_time_equals(a, b, len)) {
        /* clang-format off */
        assert(__CPROVER_forall { size_t i; (i >=0 && i < len) ==> (a[i] == b[i]) });
        /* clang-format on */
    }
}
