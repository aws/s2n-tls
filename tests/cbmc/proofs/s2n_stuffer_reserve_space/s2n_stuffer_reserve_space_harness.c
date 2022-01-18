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
#include "utils/s2n_mem.h"

void s2n_stuffer_reserve_space_harness()
{
    /* Non-deterministic inputs. */
    struct s2n_stuffer *stuffer = cbmc_allocate_s2n_stuffer();
    __CPROVER_assume(s2n_result_is_ok(s2n_stuffer_validate(stuffer)));
    uint32_t size;

    nondet_s2n_mem_init();

    /* Save previous state. */
    struct s2n_stuffer            old_stuffer = *stuffer;
    struct store_byte_from_buffer old_byte_from_stuffer;
    save_byte_from_blob(&stuffer->blob, &old_byte_from_stuffer);

    /* Operation under verification. */
    if (s2n_stuffer_reserve_space(stuffer, size) == S2N_SUCCESS) {
        assert(s2n_result_is_ok(s2n_stuffer_validate(stuffer)));
        if (s2n_stuffer_space_remaining(&old_stuffer) < size) {
            /* Always grow a stuffer by at least 1k */
            assert(stuffer->blob.size
                   == (MAX(size - s2n_stuffer_space_remaining(&old_stuffer), S2N_MIN_STUFFER_GROWTH_IN_BYTES)
                       + old_stuffer.blob.size));
            assert(stuffer->blob.allocated >= size);
        } else {
            assert_stuffer_equivalence(stuffer, &old_stuffer, &old_byte_from_stuffer);
        }
    } else {
        /*
         * s2n_realloc could fail, so we can onyl guarantee equivalence of
         * data pointer, but not the elements in it.
         */
        assert(stuffer->blob.data == old_stuffer.blob.data);
        assert(stuffer->blob.size == old_stuffer.blob.size);
        assert(stuffer->write_cursor == old_stuffer.write_cursor);
        assert(stuffer->high_water_mark == old_stuffer.high_water_mark);
        assert(stuffer->alloced == old_stuffer.alloced);
        assert(stuffer->growable == old_stuffer.growable);
        assert(stuffer->tainted == old_stuffer.tainted);
    }
}
