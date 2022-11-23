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
    uint32_t old_n = n;
    struct s2n_stuffer old_stuffer = *stuffer;

    /* Function under verification. */
    if (s2n_stuffer_wipe_n(stuffer, n) == S2N_SUCCESS) {
        assert(s2n_result_is_ok(s2n_stuffer_validate(stuffer)));
        assert(old_n == n);
        assert(S2N_IMPLIES(n >= old_stuffer.write_cursor,
                stuffer->high_water_mark == 0 && stuffer->tainted == 0 && stuffer->write_cursor == 0 && stuffer->read_cursor == 0));
        assert(S2N_IMPLIES(n < old_stuffer.write_cursor,
                (stuffer->read_cursor == MIN(old_stuffer.read_cursor, (old_stuffer.write_cursor - n)))));
        assert(S2N_IMPLIES(n < old_stuffer.write_cursor,
                (stuffer->write_cursor == old_stuffer.write_cursor - n)));
        if (n >= old_stuffer.write_cursor)
            assert_all_bytes_are(stuffer->blob.data, S2N_WIPE_PATTERN, old_stuffer.high_water_mark);
        else
            assert_all_bytes_are(stuffer->blob.data + (old_stuffer.write_cursor - n), S2N_WIPE_PATTERN, n);
    };
}
