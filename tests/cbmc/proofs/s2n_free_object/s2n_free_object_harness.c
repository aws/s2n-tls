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

#include "api/s2n.h"

void s2n_free_object_harness()
{
    /* Non-deterministic inputs. */
    uint32_t size;
    uint8_t *data = malloc(size);

    /* Assumptions. */
    nondet_s2n_mem_init();

    /* Operation under verification. */
    int result = s2n_free_object(&data, size);
    if (result == S2N_SUCCESS) {
        assert(data == NULL);
    }

    /* Cleanup after expected error cases, for memory leak check. */
    if (result != S2N_SUCCESS && s2n_errno == S2N_ERR_NOT_INITIALIZED) {
        /* `s2n_free` failed because s2n was not initialized. */
        free(data);
    }
}
