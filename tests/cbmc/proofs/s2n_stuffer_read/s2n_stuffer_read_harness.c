/*
 * Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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
#include "stuffer/s2n_stuffer.h"

void s2n_stuffer_read_harness()
{
    struct s2n_stuffer *stuffer = cbmc_allocate_s2n_stuffer();
    struct s2n_blob *   blob    = cbmc_allocate_s2n_blob();
    __CPROVER_assume(s2n_stuffer_is_valid(stuffer));
    __CPROVER_assume(s2n_blob_is_valid(blob));
    struct s2n_stuffer            old_stuffer = *stuffer;
    struct s2n_blob               old_blob    = *blob;
    struct store_byte_from_buffer old_byte;
    save_byte_from_blob(&stuffer->blob, &old_byte);

    /* int s2n_stuffer_read(struct s2n_stuffer *stuffer, struct s2n_blob *out) */
    if (s2n_stuffer_read(stuffer, blob) == S2N_SUCCESS) {
        assert(stuffer->read_cursor == old_stuffer.read_cursor + old_blob.size);
    } else {
        assert(stuffer->read_cursor == old_stuffer.read_cursor);
    }

    /* These assertions should always hold, regardless of whether the test succeeded */
    assert(stuffer->blob.data == old_stuffer.blob.data);
    assert(stuffer->blob.size == old_stuffer.blob.size);
    assert(stuffer->write_cursor == old_stuffer.write_cursor);
    assert(stuffer->high_water_mark == old_stuffer.high_water_mark);
    assert(stuffer->alloced == old_stuffer.alloced);
    assert(stuffer->growable == old_stuffer.growable);
    assert(stuffer->tainted == old_stuffer.tainted);

    assert(blob->allocated == old_blob.allocated);
    assert(blob->growable == old_blob.growable);
    assert(blob->size == old_blob.size);

    assert_byte_from_blob_matches(&stuffer->blob, &old_byte);
    assert(s2n_stuffer_is_valid(stuffer));
    assert(s2n_blob_is_valid(stuffer));
}
