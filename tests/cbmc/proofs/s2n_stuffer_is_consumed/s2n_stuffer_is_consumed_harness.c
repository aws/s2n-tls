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

#include <cbmc_proof/cbmc_utils.h>
#include <cbmc_proof/make_common_datastructures.h>

#include "api/s2n.h"
#include "stuffer/s2n_stuffer.h"

#include <assert.h>

void s2n_stuffer_is_consumed_harness()
{
    /* Non-deterministic inputs. */
    struct s2n_stuffer *stuffer = cbmc_allocate_s2n_stuffer();
    __CPROVER_assume(s2n_result_is_ok(s2n_stuffer_validate(stuffer)));

    /* Save previous state. */
    struct s2n_stuffer            old_stuffer = *stuffer;
    struct store_byte_from_buffer old_byte_from_stuffer;
    save_byte_from_blob(&stuffer->blob, &old_byte_from_stuffer);

    /* Operation under verification. */
    bool result = s2n_stuffer_is_consumed(stuffer);
    if (old_stuffer.read_cursor != old_stuffer.write_cursor) {
        assert(result == false);
    } else if (old_stuffer.tainted) {
        assert(result == false);
    } else {
        assert(result == true);
    }

    /* Post-conditions. */
    assert(s2n_result_is_ok(s2n_stuffer_validate(stuffer)));
    assert_stuffer_equivalence(stuffer, &old_stuffer, &old_byte_from_stuffer);
}
