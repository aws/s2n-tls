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

#include "api/s2n.h"
#include "utils/s2n_mem.h"

void s2n_mem_init_harness()
{
    /* Operation under verification. */
    if (s2n_mem_init() == S2N_SUCCESS) {
        assert(s2n_mem_is_init());
        assert(s2n_mem_get_page_size() > 0);
        assert(s2n_mem_get_page_size() <= UINT32_MAX);
    } else {
        assert(!s2n_mem_is_init());
    }
}
