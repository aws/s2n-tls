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

void s2n_set_len_harness()
{
    /* Non-deterministic inputs. */
    struct s2n_set *set = cbmc_allocate_s2n_set();
    __CPROVER_assume(s2n_result_is_ok(s2n_set_validate(set)));
    __CPROVER_assume(s2n_set_is_bounded(set, MAX_ARRAY_LEN, MAX_ARRAY_ELEMENT_SIZE));
    uint32_t* len = malloc(sizeof(*len));

    /* Operation under verification. */
    if(s2n_result_is_ok(s2n_set_len(set, len))) {
        /* Post-condition. */
        assert(*len == set->data->len);
    }

    /* Post-condition. */
    assert(s2n_result_is_ok(s2n_set_validate(set)));
}
