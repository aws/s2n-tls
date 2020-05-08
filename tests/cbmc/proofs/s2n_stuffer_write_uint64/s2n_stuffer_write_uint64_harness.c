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

#include "stuffer/s2n_stuffer.h"
#include "utils/s2n_safety.h"

#include <assert.h>

#include <cbmc_proof/cbmc_utils.h>
#include <cbmc_proof/make_common_datastructures.h>
#include <cbmc_proof/proof_allocators.h>

void s2n_calculate_stacktrace() {}

void s2n_stuffer_write_uint64_harness() {
    struct s2n_stuffer *stuffer = cbmc_allocate_s2n_stuffer();
    __CPROVER_assume(s2n_stuffer_is_valid(stuffer));

    uint64_t src;
    uint32_t index;
    uint32_t old_write_cursor = stuffer->write_cursor;

    /* Store a byte from the stuffer that wont be overwritten to compare if the write succeeds */
    __CPROVER_assume(index < stuffer->blob.size && (index < old_write_cursor || index >= old_write_cursor + sizeof(uint64_t)));
    uint8_t untouched_byte = stuffer->blob.data[index];

    /* Store a byte from the stuffer to compare if the write fails */
    struct store_byte_from_buffer old_byte_from_stuffer;
    save_byte_from_blob(&stuffer->blob, &old_byte_from_stuffer);

    /* Store src to compare after the write */
    uint64_t old_src = src;

    if (s2n_stuffer_write_uint64(stuffer, src) == S2N_SUCCESS) {
        assert(stuffer->write_cursor == old_write_cursor + sizeof(uint64_t));
        assert(stuffer->blob.data[index] == untouched_byte);

        /* Ensure uint was correctly written to the stuffer */
        assert(((uint64_t) stuffer->blob.data[old_write_cursor]) << 56
             | ((uint64_t) stuffer->blob.data[old_write_cursor + 1]) << 48
             | ((uint64_t) stuffer->blob.data[old_write_cursor + 2]) << 40
             | ((uint64_t) stuffer->blob.data[old_write_cursor + 3]) << 32
             | ((uint64_t) stuffer->blob.data[old_write_cursor + 4]) << 24
             | ((uint64_t) stuffer->blob.data[old_write_cursor + 5]) << 16
             | ((uint64_t) stuffer->blob.data[old_write_cursor + 6]) << 8
             | ((uint64_t) stuffer->blob.data[old_write_cursor + 7]) == src);
    } else {
        assert(stuffer->write_cursor == old_write_cursor);
        assert_byte_from_blob_matches(&stuffer->blob, &old_byte_from_stuffer);
    }

    assert(old_src == src);
    assert(s2n_stuffer_is_valid(stuffer));
}
