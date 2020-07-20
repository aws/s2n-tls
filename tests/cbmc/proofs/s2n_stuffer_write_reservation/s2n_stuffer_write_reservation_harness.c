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

#include <sys/param.h>

#include "api/s2n.h"
#include "stuffer/s2n_stuffer.h"
#include "utils/s2n_mem.h"

#include <assert.h>
#include <cbmc_proof/cbmc_utils.h>
#include <cbmc_proof/make_common_datastructures.h>
#include <cbmc_proof/nondet.h>
#include <cbmc_proof/proof_allocators.h>

void s2n_stuffer_write_reservation_harness() {
    /* Non-deterministic inputs. */
    struct s2n_stuffer_reservation *reservation = cbmc_allocate_s2n_stuffer_reservation();
    __CPROVER_assume(s2n_stuffer_reservation_is_valid(reservation));
    __CPROVER_assume(reservation->length < MAX_LENGTH);
    uint32_t u;

    /* Non-deterministically set initialized (in s2n_mem) to true. */
    if(nondet_bool()) {
        s2n_mem_init();
    }

    /* Save previous state from stuffer_reservation. */
    struct s2n_stuffer_reservation old_stuffer_reservation = *reservation;

    /* Operation under verification. */
    if (s2n_stuffer_write_reservation(reservation, u) == S2N_SUCCESS) {
        assert(s2n_stuffer_reservation_is_valid(reservation));
        assert(reservation->stuffer->write_cursor == old_stuffer_reservation.stuffer->write_cursor);
    } else {
        assert(reservation->stuffer->write_cursor == old_stuffer_reservation.stuffer->write_cursor);
        assert(reservation->stuffer->high_water_mark == old_stuffer_reservation.stuffer->high_water_mark);
    }
    assert(reservation->stuffer->alloced == old_stuffer_reservation.stuffer->alloced);
    assert(reservation->stuffer->growable == old_stuffer_reservation.stuffer->growable);
    assert(reservation->stuffer->tainted == old_stuffer_reservation.stuffer->tainted);
    assert(reservation->stuffer->read_cursor == old_stuffer_reservation.stuffer->read_cursor);
}
