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
#include "error/s2n_errno.h"
#include "stuffer/s2n_stuffer.h"

void s2n_stuffer_skip_to_char_harness()
{
    /* Non-deterministic inputs. */
    struct s2n_stuffer *stuffer = cbmc_allocate_s2n_stuffer();
    __CPROVER_assume(s2n_result_is_ok(s2n_stuffer_validate(stuffer)));
    __CPROVER_assume(s2n_blob_is_bounded(&stuffer->blob, MAX_BLOB_SIZE));
    const char target;

    /* Save previous state from stuffer. */
    struct s2n_stuffer            old_stuffer = *stuffer;
    struct store_byte_from_buffer old_byte_from_stuffer;
    save_byte_from_blob(&stuffer->blob, &old_byte_from_stuffer);

    /* Operation under verification. */
    if (s2n_stuffer_skip_to_char(stuffer, target) == S2N_SUCCESS) {
        assert(S2N_IMPLIES(s2n_stuffer_data_available(&old_stuffer) == 0,
                           stuffer->read_cursor == old_stuffer.read_cursor));
        if (s2n_stuffer_data_available(stuffer) > 0) {
            assert(stuffer->blob.data[ stuffer->read_cursor ] == target);
            size_t idx;
            __CPROVER_assume(idx >= old_stuffer.read_cursor && idx < stuffer->read_cursor);
            assert(stuffer->blob.data[ idx ] != target);
        }
    }
    assert_stuffer_immutable_fields_after_read(stuffer, &old_stuffer, &old_byte_from_stuffer);
    assert(s2n_result_is_ok(s2n_stuffer_validate(stuffer)));
}
