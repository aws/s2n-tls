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

#include "utils/s2n_annotations.h"
#include "utils/s2n_safety.h"
#include "sidetrail.h"

void* s2n_sidetrail_memset(void* ptr, int value, size_t num)
{
    uint8_t* p = (uint8_t*)(ptr);
    __VERIFIER_assert(num >= 0);
    for (size_t i = 0; i < num; ++i) {
        S2N_INVARIANT(i <= num);
        p[i] = value;
    }
}
