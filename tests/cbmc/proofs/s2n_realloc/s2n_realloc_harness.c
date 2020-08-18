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
#include "utils/s2n_blob.h"

void s2n_realloc_harness()
{
    struct s2n_blob *blob = cbmc_allocate_s2n_blob();
    __CPROVER_assume(s2n_blob_is_valid(blob));
    uint32_t size;
    size_t   index;
    __CPROVER_assume(index < blob->size || (blob->size == 0 && index == 0));

    nondet_s2n_mem_init();

    const struct s2n_blob old_blob = *blob;
    uint8_t               old_data;
    if (blob->size > 0) { old_data = blob->data[ index ]; }

    if (s2n_realloc(blob, size) == S2N_SUCCESS) {
        assert(s2n_blob_is_valid(blob));
        assert(blob->allocated >= size);
        assert(blob->size == size);
        if (size >= old_blob.size) {
            if (old_blob.size > 0) { assert(blob->data[ index ] == old_data); }

            /* Check if data at the old memory location was zeroed before freeing */
#pragma CPROVER check push
#pragma CPROVER check disable "pointer"
            if (size > old_blob.allocated) {
                if (old_blob.size > 0 && old_blob.data != NULL) {
                    size_t i;
                    __CPROVER_assume(i < old_blob.size);
                    assert(old_blob.data[ i ] == 0);
                }
            }
#pragma CPROVER check pop
        } else {
            assert_all_zeroes(blob->data + blob->size, old_blob.size - blob->size);
        }
    }
}
