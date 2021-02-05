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

#include "utils/s2n_array.h"
#include "utils/s2n_result.h"

#include <cbmc_proof/make_common_datastructures.h>

void s2n_array_capacity_harness()
{
    /* Non-deterministic inputs. */
    struct s2n_array *array = cbmc_allocate_s2n_array();
    __CPROVER_assume(s2n_result_is_ok(s2n_array_validate(array)));
    __CPROVER_assume(s2n_array_is_bounded(array, MAX_ARRAY_LEN, MAX_ARRAY_ELEMENT_SIZE));
    uint32_t* capacity = malloc(sizeof(*capacity));

    /* Operation under verification. */
    if(s2n_result_is_ok(s2n_array_capacity(array, capacity))) {
        /* Post-condition. */
        assert(*capacity == (array->mem.size / array->element_size));
    }

    /* Post-condition. */
    assert(s2n_result_is_ok(s2n_array_validate(array)));
}
