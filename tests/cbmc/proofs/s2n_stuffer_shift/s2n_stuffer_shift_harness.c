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

#include "api/s2n.h"
#include "stuffer/s2n_stuffer.h"

void s2n_stuffer_shift_harness()
{
    struct s2n_stuffer *stuffer = cbmc_allocate_s2n_stuffer();
    __CPROVER_assume(s2n_result_is_ok(s2n_stuffer_validate(stuffer)));
    __CPROVER_assume(s2n_blob_is_bounded(&stuffer->blob, MAX_BLOB_SIZE));

    /* Save previous state from stuffer. */
    struct s2n_stuffer old_stuffer = *stuffer;
    uint32_t shift = old_stuffer.read_cursor;
    struct store_byte_from_buffer old_byte = { 0 };
    save_byte_from_blob(&old_stuffer.blob, &old_byte);
    __CPROVER_assume(old_byte.idx >= old_stuffer.read_cursor);
    __CPROVER_assume(old_byte.idx < old_stuffer.write_cursor);

    int result = s2n_stuffer_shift(stuffer);
    assert(s2n_result_is_ok(s2n_stuffer_validate(stuffer)));

    if (result == S2N_SUCCESS) {
        old_byte.idx -= shift;
        old_stuffer.write_cursor -= shift;
        old_stuffer.read_cursor = 0;
    }
    assert_stuffer_equivalence(stuffer, &old_stuffer, &old_byte);
}
