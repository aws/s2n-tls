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

#include "api/s2n.h"
#include "error/s2n_errno.h"
#include "utils/s2n_blob.h"

void s2n_blob_is_growable_harness()
{
    /* Non-deterministic inputs. */
    struct s2n_blob *blob = cbmc_allocate_s2n_blob();
    __CPROVER_assume(S2N_IMPLIES(blob != NULL, s2n_result_is_ok(s2n_blob_validate(blob))));

    /* Operation under verification. */
    if (s2n_blob_is_growable(blob)) {
        assert(blob->growable || (blob->data == NULL && blob->size == 0 && blob->allocated == 0));
    }

    /* Post-condition. */
    if (blob != NULL) assert(s2n_result_is_ok(s2n_blob_validate(blob)));
}
