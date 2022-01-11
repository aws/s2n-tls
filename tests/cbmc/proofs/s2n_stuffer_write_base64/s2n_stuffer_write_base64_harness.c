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
#include "utils/s2n_mem.h"

void s2n_stuffer_write_base64_harness()
{
    struct s2n_stuffer *stuffer = cbmc_allocate_s2n_stuffer();
    __CPROVER_assume(s2n_result_is_ok(s2n_stuffer_validate(stuffer)));

    struct s2n_stuffer *in = cbmc_allocate_s2n_stuffer();
    __CPROVER_assume(s2n_result_is_ok(s2n_stuffer_validate(in)));
    __CPROVER_assume(s2n_blob_is_bounded(&in->blob, MAX_BLOB_SIZE));

    /* Save previous state from stuffer. */
    struct s2n_stuffer old_stuffer = *stuffer;

    /* Save previous state from out. */
    struct s2n_stuffer            old_in = *in;
    struct store_byte_from_buffer old_byte_from_in;
    save_byte_from_blob(&in->blob, &old_byte_from_in);

    nondet_s2n_mem_init();

    if (s2n_stuffer_write_base64(stuffer, in) == S2N_SUCCESS) {
        assert(s2n_result_is_ok(s2n_stuffer_validate(stuffer)));
        if (s2n_stuffer_data_available(&old_stuffer) >= 2) {
            size_t idx;
            __CPROVER_assume(idx >= old_stuffer.write_cursor && idx < stuffer->write_cursor);
            assert(s2n_is_base64_char(stuffer->blob.data[ idx ]));
        }
    }

    assert_stuffer_immutable_fields_after_read(in, &old_in, &old_byte_from_in);
    assert(s2n_result_is_ok(s2n_stuffer_validate(in)));
}
