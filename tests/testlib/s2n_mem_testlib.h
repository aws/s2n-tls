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

#pragma once

#include "utils/s2n_result.h"

struct s2n_mem_test_malloc {
    void *ptr;
    uint32_t requested;
    uint32_t allocated;
    bool freed;
};

struct s2n_mem_test_cb_scope {
    uint8_t _reserve;
};

S2N_RESULT s2n_mem_test_init_callbacks(void *ctx);
S2N_CLEANUP_RESULT s2n_mem_test_free_callbacks(void *ctx);
S2N_RESULT s2n_mem_test_wipe_callbacks();

S2N_RESULT s2n_mem_test_assert_malloc_count(uint32_t count);
S2N_RESULT s2n_mem_test_assert_malloc(uint32_t requested);
S2N_RESULT s2n_mem_test_assert_all_freed();
