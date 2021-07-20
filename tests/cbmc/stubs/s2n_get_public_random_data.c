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

#include <cbmc_proof/nondet.h>
#include "utils/s2n_blob.h"

S2N_RESULT s2n_get_public_random_data(struct s2n_blob *blob) 
{
    /* Note: We want to havoc all bytes in the region
     * blob->data[0..blob->size-1],
     * but __CPROVER_havoc_object(blob->data) does more,
     * it havoc the entire struct containing the blob.
     * 
     * Instead we havoc a single byte in that region,
     * which should be sufficent to catch most issues. */

    if (blob->size != 0) {
        size_t i = nondet_size_t();
        __CPROVER_assume(i < blob->size);

        blob->data[i] = nondet_uint8_t();
    }
    
    return nondet_bool() ? S2N_RESULT_OK : S2N_RESULT_ERROR;
}
