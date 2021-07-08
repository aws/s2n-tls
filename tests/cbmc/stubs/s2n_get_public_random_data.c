/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"). You may not use
 * this file except in compliance with the License. A copy of the License is
 * located at
 *
 *     http://aws.amazon.com/apache2.0/
 *
 * or in the "license" file accompanying this file. This file is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 * implied. See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <assert.h>
#include <cbmc_proof/nondet.h>
#include "api/s2n.h"
#include "utils/s2n_result.h"
#include "utils/s2n_blob.h"
#include "utils/s2n_safety_macros.h"


S2N_RESULT s2n_get_public_random_data(struct s2n_blob *blob) 
{
    assert(s2n_blob_validate(blob) == S2N_RESULT_OK);
    assert(__CPROVER_w_ok(blob->data, blob->size));

    /* FIXME: This is havoking too much it should havoc only 
     * blob->data[0..blob->size-1], but we don't have a good
     * way to do that apparently. */
    __CPROVER_havok_object(blob->data);
    
    bool ok = nondet_bool();
    return ok ? S2N_RESULT_OK : S2N_RESULT_ERROR;
}