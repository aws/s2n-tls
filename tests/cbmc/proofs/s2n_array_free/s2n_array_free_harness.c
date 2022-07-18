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

#include <assert.h>

void s2n_array_free_harness()
{
    /* Non-deterministic inputs. */
    struct s2n_array *array = cbmc_allocate_s2n_array();

    /* Assumptions. */
    nondet_s2n_mem_init();
    __CPROVER_assume(s2n_result_is_ok(s2n_array_validate(array)));

    /* Operation under verification. */
    s2n_result result = s2n_array_free(array);
    if (s2n_result_is_error(result)) {
        assert(s2n_errno != S2N_ERR_FREE_STATIC_BLOB);
    }

    /**
     * Cleanup after expected error cases, for memory leak check.
     * It's good proof practice not to mix state mutations (below) with property checks (above).
     */
    if (s2n_result_is_error(result) && s2n_errno == S2N_ERR_NOT_INITIALIZED) {
        /* s2n was not initialized, this failure is expected. */
        free(array->mem.data);
        free(array);
    }
}
