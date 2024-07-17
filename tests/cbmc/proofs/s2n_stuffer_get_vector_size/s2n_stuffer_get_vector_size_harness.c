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

#include "api/s2n.h"
#include "stuffer/s2n_stuffer.h"

void s2n_stuffer_get_vector_size_harness()
{
    nondet_s2n_mem_init();

    struct s2n_stuffer_reservation *reservation = cbmc_allocate_s2n_stuffer_reservation();
    __CPROVER_assume(s2n_result_is_ok(s2n_stuffer_reservation_validate(reservation)));

    uint32_t output = 0;
    assert(s2n_stuffer_get_vector_size(reservation, &output) == S2N_SUCCESS);

    assert(s2n_result_is_ok(s2n_stuffer_reservation_validate(reservation)));
    uint32_t expected_output = reservation->stuffer->write_cursor -
            (reservation->write_cursor + reservation->length);
    assert(expected_output == output);
}
