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

#include <assert.h>
#include <cbmc_proof/cbmc_utils.h>
#include <cbmc_proof/make_common_datastructures.h>
#include <cbmc_proof/proof_allocators.h>

#include "api/s2n.h"

void s2n_free_object_harness()
{
    uint32_t size;
    uint8_t *data     = can_fail_malloc(size);
    uint8_t *old_data = data;

    nondet_s2n_mem_init();

    if (s2n_free_object(&data, size) == S2N_SUCCESS) { assert(data == NULL); }

#pragma CPROVER check push
#pragma CPROVER check disable "pointer"
    /* Verify that the memory was zeroed */
    if (size > 0 && old_data != NULL) {
        size_t i;
        __CPROVER_assume(i < size);
        assert(old_data[ i ] == 0);
    }
#pragma CPROVER check pop
}
