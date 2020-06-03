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
#include <cbmc_proof/make_common_datastructures.h>
#include <cbmc_proof/proof_allocators.h>

#include "api/s2n.h"
#include "error/s2n_errno.h"
#include "utils/s2n_blob.h"

void s2n_blob_init_harness()
{
    /* Non-deterministic inputs. */
    struct s2n_blob *blob = can_fail_malloc(sizeof(*blob));
    uint32_t         size;
    uint8_t *        data = can_fail_malloc(size);

    /* Pre-conditions. */
    __CPROVER_assume(S2N_IMPLIES(size != 0, data != NULL));

    /* Operation under verification. */
    if (s2n_blob_init(blob, data, size) == S2N_SUCCESS) { assert(s2n_blob_is_valid(blob)); }
}
