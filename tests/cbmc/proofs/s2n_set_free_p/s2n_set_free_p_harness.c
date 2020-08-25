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

#include "api/s2n.h"
#include "utils/s2n_set.h"
#include "utils/s2n_result.h"

#include <assert.h>
#include <cbmc_proof/proof_allocators.h>
#include <cbmc_proof/make_common_datastructures.h>

void s2n_set_free_p_harness()
{
    /* Non-deterministic inputs. */
    struct s2n_set *set = cbmc_allocate_s2n_set();
    __CPROVER_assume(s2n_result_is_ok(s2n_set_validate(set)));

    nondet_s2n_mem_init();

    struct s2n_set old_set = *set;

    /* Operation under verification. */
    if(s2n_result_is_ok(s2n_set_free_p(&set))) {
        assert(set == NULL);
    }
#pragma CPROVER check push
#pragma CPROVER check disable "pointer"
    /*
     * Regardless of the result of s2n_free, verify that the
     * data pointed to in the blob was zeroed.
     */
    if (old_set.data->mem.size > 0 && old_set.data->mem.data != NULL) {
        size_t i;
        __CPROVER_assume(i < old_set.data->mem.size);
        assert(old_set.data->mem.data[i] == 0);
    }
#pragma CPROVER check pop
}
