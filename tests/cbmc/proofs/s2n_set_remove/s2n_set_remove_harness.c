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

#include "utils/s2n_set.h"

#include <cbmc_proof/make_common_datastructures.h>

#include <assert.h>

void s2n_set_remove_harness()
{
    /* Non-deterministic inputs. */
    struct s2n_set *set = cbmc_allocate_s2n_set();
    __CPROVER_assume(s2n_result_is_ok(s2n_set_validate(set)));
    __CPROVER_assume(s2n_set_is_bounded(set, MAX_ARRAY_LEN, MAX_ARRAY_ELEMENT_SIZE));
    uint32_t idx;

    struct s2n_array old_array = *(set->data);
    struct store_byte_from_buffer old_byte;
    if (set->data->len != 0) save_byte_from_array(set->data->mem.data, set->data->len - 1, &old_byte);

    /* Operation under verification. */
    if(s2n_result_is_ok(s2n_set_remove(set, idx))) {
        /* Post-conditions. */
        assert(set->data->mem.data != NULL);
        assert(S2N_IMPLIES(old_array.len != 0, set->data->len == (old_array.len - 1)));
        assert(idx < old_array.len);
        if(set->data->len != 0 && idx == old_array.len - 1) {
            assert_byte_from_blob_matches(&set->data->mem, &old_byte);
        }
    }

    assert(s2n_result_is_ok(s2n_set_validate(set)));
}
