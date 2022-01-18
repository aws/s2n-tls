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
#include <sys/param.h>

#include "api/s2n.h"
#include "stuffer/s2n_stuffer.h"

void s2n_stuffer_skip_write_harness()
{
    /* Non-deterministic inputs. */
    struct s2n_stuffer *stuffer = cbmc_allocate_s2n_stuffer();
    __CPROVER_assume(s2n_result_is_ok(s2n_stuffer_validate(stuffer)));
    uint32_t data_len;

    nondet_s2n_mem_init();

    /* Save previous state from stuffer. */
    struct s2n_stuffer old_stuffer = *stuffer;
    /* Store a byte from the stuffer to compare */
    struct store_byte_from_buffer old_byte_from_stuffer;
    save_byte_from_blob(&stuffer->blob, &old_byte_from_stuffer);

    /* Operation under verification. */
    if (s2n_stuffer_skip_write(stuffer, data_len) == S2N_SUCCESS) {
        assert(stuffer->write_cursor == old_stuffer.write_cursor + data_len);
        assert(stuffer->high_water_mark == MAX(old_stuffer.write_cursor + data_len, old_stuffer.high_water_mark));
        if (old_stuffer.blob.size > 0) { assert_byte_from_blob_matches(&stuffer->blob, &old_byte_from_stuffer); }
        assert(s2n_result_is_ok(s2n_stuffer_validate(stuffer)));
    } else {
        assert(stuffer->write_cursor == old_stuffer.write_cursor);
        assert(stuffer->high_water_mark == old_stuffer.high_water_mark);
    }
}
