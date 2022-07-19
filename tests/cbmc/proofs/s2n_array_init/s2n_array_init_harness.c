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

#include <cbmc_proof/make_common_datastructures.h>
#include <cbmc_proof/cbmc_utils.h>

#include <assert.h>

void s2n_array_init_harness()
{
    /* Non-deterministic inputs. */
    uint32_t element_size;
    struct s2n_array *array = cbmc_allocate_s2n_array();

    nondet_s2n_mem_init();

    /* Operation under verification. */
    if (s2n_result_is_ok(s2n_array_init(array, element_size))) {

        /* Post-conditions. */
        assert(s2n_result_is_ok(s2n_array_validate(array)));
        assert_all_zeroes((uint8_t*) &array->mem, sizeof(array->mem));
        assert(array->element_size == element_size);
        assert(array->len == 0);
    }
}
