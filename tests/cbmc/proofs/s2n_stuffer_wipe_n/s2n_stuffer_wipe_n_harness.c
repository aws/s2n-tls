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
#include <cbmc_proof/make_common_datastructures.h>
#include <sys/param.h>

#include "api/s2n.h"
#include "stuffer/s2n_stuffer.h"

void s2n_stuffer_wipe_n_harness()
{
    /* Non-deterministic inputs. */
    struct s2n_stuffer *stuffer = cbmc_allocate_s2n_stuffer();
    uint32_t n;

    /* Assume preconditions. */
    __CPROVER_assume(s2n_result_is_ok(s2n_stuffer_validate(stuffer)));

    /* Save previous state. */
    struct s2n_stuffer old_stuffer = *stuffer;

    /* Save byte from untouched portion to compare after the wipe */
    uint32_t expect_wiped = MIN(n, old_stuffer.write_cursor);
    uint32_t expected_write_cursor = old_stuffer.write_cursor - expect_wiped;
    uint32_t expected_wipe_span = old_stuffer.high_water_mark - expected_write_cursor;
    struct store_byte_from_buffer old_byte;
    save_byte_from_array(old_stuffer.blob.data, expected_write_cursor, &old_byte);

    /* Given a valid stuffer, wipe_n always succeeds */
    assert(s2n_stuffer_wipe_n(stuffer, n) == S2N_SUCCESS);
    assert(s2n_result_is_ok(s2n_stuffer_validate(stuffer)));

    /* high_water_mark is lowered to the new write cursor */
    assert(stuffer->high_water_mark == expected_write_cursor);
    assert(stuffer->tainted == old_stuffer.tainted);
    assert(stuffer->blob == old_stuffer.blob);
    assert(stuffer->blob.data == old_stuffer.blob.data);

    /* The read and write cursors should be updated */
    assert(S2N_IMPLIES(expect_wiped < n, stuffer->write_cursor == 0));
    assert(S2N_IMPLIES(expect_wiped < n, stuffer->read_cursor == 0));
    assert(stuffer->write_cursor == expected_write_cursor);
    assert(stuffer->read_cursor == MIN(old_stuffer.read_cursor, stuffer->write_cursor));

    /* Any data before the new write cursor should NOT be updated */
    if (expected_write_cursor > 0) {
        assert_byte_from_buffer_matches(stuffer->blob.data, &old_byte);
    }

    /* From the new write cursor through the old high water mark should be wiped */
    if (expected_wipe_span > 0) {
        assert_all_bytes_are(stuffer->blob.data + stuffer->write_cursor,
                S2N_WIPE_PATTERN, expected_wipe_span);
    }
}
