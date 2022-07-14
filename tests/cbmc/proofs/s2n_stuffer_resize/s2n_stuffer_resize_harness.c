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
#include "error/s2n_errno.h"
#include "stuffer/s2n_stuffer.h"

#include <assert.h>

void s2n_stuffer_resize_harness()
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
    if (s2n_stuffer_resize(stuffer, size) == S2N_SUCCESS) {
        assert(!stuffer->tainted);
        assert(stuffer->growable);
        assert(stuffer->blob.size == size);
        assert(s2n_result_is_ok(s2n_stuffer_validate(stuffer)));

        if (size == old_stuffer.blob.size) {
            assert_stuffer_equivalence(stuffer, &old_stuffer, &old_byte_from_stuffer);
        } else if (size == 0) {
            assert(stuffer->blob.data == NULL);
            assert(stuffer->blob.size == 0);
            assert(stuffer->blob.allocated == 0);
            assert(stuffer->blob.growable == 0);
        } else if (size > old_stuffer.blob.size) {
            if (size < old_stuffer.blob.allocated) {
                assert(stuffer->blob.data == old_stuffer.blob.data);
                assert(stuffer->blob.allocated == old_stuffer.blob.allocated);
                assert(stuffer->blob.growable == old_stuffer.blob.growable);
            } else {
                /* Confirms bytes were maintained. */
                if (old_stuffer.blob.size > 0)
                    assert_byte_from_buffer_matches(stuffer->blob.data, &old_byte_from_stuffer);
                assert(stuffer->blob.growable == 1);
            }
        } else { /* size < old_stuffer.blob.size */
            size_t idx;
            /* Confirms wiped portion. */
            __CPROVER_assume(idx >= size && idx < old_stuffer.blob.size);
            assert(stuffer->blob.data[ idx ] == S2N_WIPE_PATTERN);
            assert(stuffer->blob.allocated == old_stuffer.blob.allocated);
            assert(stuffer->blob.growable == old_stuffer.blob.growable);
        }
    } else {
        assert(stuffer->alloced == old_stuffer.alloced);
        assert(stuffer->growable == old_stuffer.growable);
        assert(stuffer->tainted == old_stuffer.tainted);
    }
}
