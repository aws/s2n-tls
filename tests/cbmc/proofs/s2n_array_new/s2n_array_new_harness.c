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
#include "error/s2n_errno.h"
#include "utils/s2n_array.h"
#include "utils/s2n_mem.h"

#include <assert.h>
#include <cbmc_proof/proof_allocators.h>
#include <cbmc_proof/make_common_datastructures.h>

void s2n_array_new_harness()
{
    /* Non-deterministic inputs. */
    uint32_t element_size;

    nondet_s2n_mem_init();

    /* Operation under verification. */
    struct s2n_array *new_array = s2n_array_new(element_size);

    /* Post-conditions. */
    assert(S2N_IMPLIES(new_array != NULL, s2n_result_is_ok(s2n_array_validate(new_array))));
}
