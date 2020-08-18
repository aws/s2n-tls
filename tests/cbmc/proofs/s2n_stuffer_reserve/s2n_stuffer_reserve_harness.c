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
#include <cbmc_proof/nondet.h>
#include <cbmc_proof/proof_allocators.h>
#include <sys/param.h>

#include "api/s2n.h"
#include "stuffer/s2n_stuffer.h"
#include "utils/s2n_mem.h"

void s2n_stuffer_reserve_harness()
{
    /* Non-deterministic inputs. */
    struct s2n_stuffer *stuffer = cbmc_allocate_s2n_stuffer();
    __CPROVER_assume(s2n_stuffer_is_valid(stuffer));
    struct s2n_stuffer_reservation *reservation = cbmc_allocate_s2n_stuffer_reservation();
    const uint8_t                   length;

    /* Non-deterministically set initialized (in s2n_mem) to true. */
    if (nondet_bool()) { s2n_mem_init(); }

    /* Save previous state from stuffer. */
    struct s2n_stuffer old_stuffer = *stuffer;
    /* Store a byte from the stuffer to compare */
    struct store_byte_from_buffer old_byte_from_stuffer;
    save_byte_from_blob(&stuffer->blob, &old_byte_from_stuffer);

    /* Operation under verification. */
    if (s2n_stuffer_reserve(stuffer, reservation, length) == S2N_SUCCESS) {
        assert(stuffer->write_cursor == old_stuffer.write_cursor + length);
        assert(stuffer->high_water_mark == MAX(old_stuffer.write_cursor + length, old_stuffer.high_water_mark));
        assert(reservation->length == length);
        if (old_stuffer.blob.size > 0 && reservation->length > 0) {
            size_t index;
            __CPROVER_assume(index >= reservation->write_cursor
                             && index < (reservation->write_cursor + reservation->length));
            assert(stuffer->blob.data[ index ] == S2N_WIPE_PATTERN);
            assert(reservation->stuffer->blob.data[ index ] == S2N_WIPE_PATTERN);
        }
        assert(stuffer == reservation->stuffer);
        assert(s2n_stuffer_is_valid(stuffer));
        assert(s2n_stuffer_reservation_is_valid(reservation));
    } else {
        assert(stuffer->read_cursor == old_stuffer.read_cursor);
        assert(stuffer->alloced == old_stuffer.alloced);
        assert(stuffer->growable == old_stuffer.growable);
        assert(stuffer->tainted == old_stuffer.tainted);
    }
}
