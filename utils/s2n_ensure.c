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

#include "utils/s2n_safety.h"

void *s2n_ensure_memcpy_trace(void *restrict to, const void *restrict from, size_t size, const char *debug_str)
{
    if (to == NULL || from == NULL) {
        s2n_errno = S2N_ERR_NULL;
        s2n_debug_str = debug_str;
        return NULL;
    }

    /* use memmove instead of memcpy since it'll handle overlapping regions and not result in UB */
    return memmove(to, from, size);
}
