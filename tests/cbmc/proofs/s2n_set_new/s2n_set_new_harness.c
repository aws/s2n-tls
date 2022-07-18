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

void s2n_set_new_harness()
{
    /* Non-deterministic inputs. */
    uint32_t element_size;
    int (*nondet_compare_ptr)(void*,void*) = nondet_bool() ? &nondet_compare : NULL;

    nondet_s2n_mem_init();

    /* Operation under verification. */
    struct s2n_set *new_set = s2n_set_new(element_size, nondet_compare_ptr);

    /* Post-conditions. */
    assert(S2N_IMPLIES(new_set != NULL, s2n_result_is_ok(s2n_set_validate(new_set))));
}
