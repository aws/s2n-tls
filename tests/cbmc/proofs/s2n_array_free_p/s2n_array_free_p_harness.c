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

#include "utils/s2n_result.h"

#include <cbmc_proof/make_common_datastructures.h>

void s2n_array_free_p_harness()
{
    /* Non-deterministic inputs. */
    struct s2n_array *array = cbmc_allocate_s2n_array();
    __CPROVER_assume(s2n_result_is_ok(s2n_array_validate(array)));

    nondet_s2n_mem_init();

    struct s2n_array old_array = *array;

    /* Operation under verification. */
    if(s2n_result_is_ok(s2n_array_free_p(&array))) {
        assert(array == NULL);
    }
#pragma CPROVER check push
#pragma CPROVER check disable "pointer"
    /*
     * Regardless of the result of s2n_free, verify that the
     * data pointed to in the blob was zeroed.
     */
    if (old_array.mem.size > 0 && old_array.mem.data != NULL) {
        size_t i;
        __CPROVER_assume(i < old_array.mem.size);
        assert(old_array.mem.data[i] == 0);
    }
#pragma CPROVER check pop
}
