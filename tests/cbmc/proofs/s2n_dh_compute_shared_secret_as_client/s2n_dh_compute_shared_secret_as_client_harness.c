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
#include "crypto/s2n_dhe.h"
#include "stuffer/s2n_stuffer.h"

void s2n_dh_compute_shared_secret_as_client_harness()
{
    /* Non-deterministic inputs. */
    struct s2n_dh_params *server_dh_params = cbmc_allocate_dh_params();
    struct s2n_stuffer *  Yc_out           = cbmc_allocate_s2n_stuffer();
    struct s2n_blob *     shared_key       = cbmc_allocate_s2n_blob();

    /* Assumptions. */
    nondet_s2n_mem_init();

    /* Operation under verification. */
    if (s2n_dh_compute_shared_secret_as_client(server_dh_params, Yc_out, shared_key) == S2N_SUCCESS) {
        /* Postconditions. */
        assert(s2n_result_is_ok(s2n_stuffer_validate(Yc_out)));
    }
}
