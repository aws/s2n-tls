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
#include "utils/s2n_safety.h"

int s2n_add_overflow_harness()
{
    uint32_t  a;
    uint32_t  b;
    uint32_t *out = malloc(sizeof(uint32_t));

    if (s2n_add_overflow(a, b, out) == S2N_SUCCESS) {
        assert(*out == a + b);
    } else {
        assert(( uint64_t )a + ( uint64_t )b > UINT32_MAX || out == NULL);
    }
}
