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
#include "utils/s2n_mem.h"

void s2n_stuffer_read_base64_harness()
{
    struct s2n_stuffer *stuffer = cbmc_allocate_s2n_stuffer();
    __CPROVER_assume(s2n_stuffer_is_valid(stuffer));
    __CPROVER_assume(s2n_blob_is_bounded(&stuffer->blob, MAX_BLOB_SIZE));

    struct s2n_stuffer *out = cbmc_allocate_s2n_stuffer();
    __CPROVER_assume(s2n_stuffer_is_valid(out));

    /* Save previous state from stuffer. */
    struct s2n_stuffer            old_stuffer = *stuffer;
    struct store_byte_from_buffer old_byte_from_stuffer;
    save_byte_from_blob(&stuffer->blob, &old_byte_from_stuffer);

    /* Save previous state from out. */
    struct s2n_stuffer old_out = *out;

    nondet_s2n_mem_init();

    if (s2n_stuffer_read_base64(stuffer, out) == S2N_SUCCESS) {
        assert(s2n_stuffer_is_valid(out));
        if (s2n_stuffer_data_available(&old_stuffer) >= 4) {
            size_t index;
            __CPROVER_assume(index >= old_stuffer.read_cursor && index < old_stuffer.write_cursor);
            assert(s2n_is_base64_char(stuffer->blob.data[ index ]));
        }
    }

    assert_stuffer_immutable_fields_after_read(stuffer, &old_stuffer, &old_byte_from_stuffer);
    assert(s2n_stuffer_is_valid(stuffer));
}
