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
#include "utils/s2n_blob.h"

#include <assert.h>
#include <cbmc_proof/cbmc_utils.h>
#include <cbmc_proof/proof_allocators.h>
#include <cbmc_proof/make_common_datastructures.h>

void s2n_blob_slice_harness()
{
    /* Non-deterministic inputs. */
    struct s2n_blob *blob = cbmc_allocate_s2n_blob();
    __CPROVER_assume(s2n_blob_is_valid(blob));
    struct s2n_blob *slice = cbmc_allocate_s2n_blob();
    __CPROVER_assume(s2n_blob_is_valid(slice));
    uint32_t offset;
    uint32_t size;

    /* Save previous state. */
    struct s2n_blob old_blob = *blob;
    struct store_byte_from_buffer old_byte_from_blob;
    save_byte_from_blob(blob, &old_byte_from_blob);
    struct s2n_blob old_slice = *slice;
    struct store_byte_from_buffer old_byte_from_slice;
    save_byte_from_blob(slice, &old_byte_from_slice);

    /* Operation under verification. */
    if(s2n_blob_slice(blob, slice, offset, size) == S2N_SUCCESS) {
        assert(blob->size >= offset + size);
        assert(slice->size == size);
        assert(slice->growable == 0);
        assert(slice->allocated == 0);
        assert_bytes_match(blob->data+offset, slice->data, slice->size);
    } else {
        assert_blob_equivalence(slice, &old_slice, &old_byte_from_slice);
    }
    assert(s2n_blob_is_valid(slice));
    assert(s2n_blob_is_valid(blob));
    assert_blob_equivalence(blob, &old_blob, &old_byte_from_blob);
}
