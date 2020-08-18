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
#include <cbmc_proof/proof_allocators.h>

#include "api/s2n.h"
#include "stuffer/s2n_stuffer.h"

void s2n_stuffer_rewrite_harness()
{
    /* Non-deterministic inputs. */
    struct s2n_stuffer *stuffer = cbmc_allocate_s2n_stuffer();
    __CPROVER_assume(s2n_stuffer_is_valid(stuffer));

    /* Save previous state from stuffer. */
    struct s2n_stuffer old_stuffer = *stuffer;
    /* Store a byte from the stuffer to compare after the read */
    struct store_byte_from_buffer old_byte_from_stuffer;
    save_byte_from_blob(&stuffer->blob, &old_byte_from_stuffer);

    /* Operation under verification. */
    s2n_stuffer_rewrite(stuffer);

    /* Post-conditions. */
    assert(stuffer->write_cursor == 0);
    assert(stuffer->read_cursor == 0);
    assert(stuffer->high_water_mark == old_stuffer.high_water_mark);
    assert(stuffer->alloced == old_stuffer.alloced);
    assert(stuffer->growable == old_stuffer.growable);
    assert(stuffer->tainted == old_stuffer.tainted);
    assert_blob_equivalence(&stuffer->blob, &old_stuffer.blob, &old_byte_from_stuffer);
    assert(s2n_stuffer_is_valid(stuffer));
}
