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
#include "stuffer/s2n_stuffer.h"

void s2n_stuffer_skip_whitespace_harness()
{
    /* Non-deterministic inputs. */
    struct s2n_stuffer *stuffer = cbmc_allocate_s2n_stuffer();
    __CPROVER_assume(s2n_stuffer_is_valid(stuffer));
    __CPROVER_assume(s2n_blob_is_bounded(&stuffer->blob, MAX_BLOB_SIZE));
    uint32_t skipped;

    /* Save previous state from stuffer. */
    struct s2n_stuffer            old_stuffer = *stuffer;
    struct store_byte_from_buffer old_byte_from_stuffer;
    save_byte_from_blob(&stuffer->blob, &old_byte_from_stuffer);

    /* Operation under verification. */
    if (s2n_stuffer_skip_whitespace(stuffer, &skipped) == S2N_SUCCESS) {
        size_t index;
        if (skipped > 0) {
            assert(stuffer->read_cursor == old_stuffer.read_cursor + skipped);
            __CPROVER_assume(index >= old_stuffer.read_cursor && index < stuffer->read_cursor);
            assert(stuffer->blob.data[ index ] == ' ' || stuffer->blob.data[ index ] == '\t'
                   || stuffer->blob.data[ index ] == '\n' || stuffer->blob.data[ index ] == '\r');
        } else {
            assert((stuffer->read_cursor >= stuffer->write_cursor)
                   || (stuffer->blob.data[ old_stuffer.read_cursor ] != ' '
                       && stuffer->blob.data[ old_stuffer.read_cursor ] != '\t'
                       && stuffer->blob.data[ old_stuffer.read_cursor ] != '\n'
                       && stuffer->blob.data[ old_stuffer.read_cursor ] != '\r'));
        }
    }
    assert_stuffer_immutable_fields_after_read(stuffer, &old_stuffer, &old_byte_from_stuffer);
    assert(s2n_stuffer_is_valid(stuffer));
}
