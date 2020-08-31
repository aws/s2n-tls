/*
 * Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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
#include <cbmc_proof/proof_allocators.h>

#include "api/s2n.h"
#include "error/s2n_errno.h"
#include "stuffer/s2n_stuffer.h"
#include "utils/s2n_mem.h"

void s2n_stuffer_growable_alloc_harness()
{
    /* Non-deterministic inputs. */
    struct s2n_stuffer *stuffer = cbmc_allocate_s2n_stuffer();
    __CPROVER_assume(s2n_stuffer_is_valid(stuffer));
    uint32_t size;

    /* Save previous state from stuffer. */
    struct s2n_stuffer old_stuffer = *stuffer;

    nondet_s2n_mem_init();

    /* Operation under verification. */
    if (s2n_stuffer_growable_alloc(stuffer, size) == S2N_SUCCESS) {
        /* Post-conditions. */
        assert(stuffer->growable);
        assert(stuffer->alloced);
        assert(stuffer->blob.size == size);
        assert(s2n_stuffer_is_valid(stuffer));
    } else {
        assert(stuffer->blob.data == NULL);
        assert(stuffer->blob.size == 0);
        assert(stuffer->read_cursor == 0);
        assert(stuffer->write_cursor == 0);
        assert(stuffer->high_water_mark == 0);
        assert(stuffer->alloced == 0);
        assert(stuffer->growable == 0);
        assert(stuffer->tainted == 0);
    }
}
