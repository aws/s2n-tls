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

#include <sys/param.h>
#include "utils/s2n_array.h"
#include "utils/s2n_result.h"

#include <cbmc_proof/make_common_datastructures.h>

#include <assert.h>

void s2n_array_insert_harness()
{
    /* Non-deterministic inputs. */
    struct s2n_array *array = cbmc_allocate_s2n_array();
    __CPROVER_assume(s2n_result_is_ok(s2n_array_validate(array)));
    __CPROVER_assume(s2n_array_is_bounded(array, MAX_ARRAY_LEN, MAX_ARRAY_ELEMENT_SIZE));
    uint32_t idx;
    void **element = malloc(sizeof(void *));

    nondet_s2n_mem_init();

    struct s2n_array old_array = *array;
    struct store_byte_from_buffer old_byte;
    save_byte_from_array(array->mem.data, array->len, &old_byte);

    /* Operation under verification. */
    if (s2n_result_is_ok(s2n_array_insert(array, idx, element))) {
       /*
        * In the case s2n_array_insert is successful, we can ensure the array isn't empty
        * and index is within bounds.
        */
        assert(array->mem.data != NULL);
        assert(array->len == (old_array.len + 1));
        assert(idx < array->len);
        assert(*element == (array->mem.data + (array->element_size * idx)));
        assert(s2n_result_is_ok(s2n_array_validate(array)));
        if (old_array.len != 0 && idx == old_array.len) {
            assert_byte_from_blob_matches(&array->mem, &old_byte);
        }

        /* Verify the array capacity increases by the correct amount. */
        uint32_t old_capacity = old_array.mem.size / old_array.element_size;
        if (old_array.len >= old_capacity) {
            uint32_t expected_new_capacity = MAX(S2N_INITIAL_ARRAY_SIZE, old_capacity * 2) * old_array.element_size;
            uint32_t new_capacity = array->mem.size;
            assert(new_capacity == expected_new_capacity);
        }
    }
}
