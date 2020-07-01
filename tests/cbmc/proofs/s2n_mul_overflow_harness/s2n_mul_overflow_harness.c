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

#include "api/s2n.h"
#include "utils/s2n_safety.h"

#include <assert.h>
#include <cbmc_proof/proof_allocators.h>
#include <cbmc_proof/make_common_datastructures.h>

int s2n_mul_overflow_harness()
{
    uint32_t a;
    uint32_t b;
    uint32_t *out = can_fail_malloc(sizeof(uint32_t));

    /* a check on *out == a*b should be added here but the CBMC checking is too slow */
    /* the checking of assert(__CPROVER_overflow_mult(a, b)==false) is also slow */
    s2n_mul_overflow(a, b, out);
}