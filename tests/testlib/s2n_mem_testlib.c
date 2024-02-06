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

#include "testlib/s2n_mem_testlib.h"

#include "stuffer/s2n_stuffer.h"
#include "utils/s2n_mem.h"
#include "utils/s2n_safety.h"

struct s2n_mem_test_cb_ctx {
    struct s2n_stuffer mallocs;
} s2n_mem_test_ctx = { 0 };

static s2n_mem_malloc_callback s2n_mem_malloc_cb_backup = NULL;
static s2n_mem_free_callback s2n_mem_free_cb_backup = NULL;

static int s2n_mem_test_malloc_cb(void **ptr, uint32_t requested, uint32_t *allocated);
static int s2n_mem_test_free_cb(void *ptr, uint32_t size);

static S2N_RESULT s2n_mem_test_set_callbacks()
{
    s2n_mem_init_callback mem_init_cb = NULL;
    s2n_mem_cleanup_callback mem_cleanup_cb = NULL;
    s2n_mem_malloc_callback mem_malloc_cb = NULL;
    s2n_mem_free_callback mem_free_cb = NULL;
    RESULT_GUARD(s2n_mem_get_callbacks(&mem_init_cb, &mem_cleanup_cb, &mem_malloc_cb, &mem_free_cb));

    if (mem_malloc_cb != s2n_mem_test_malloc_cb) {
        s2n_mem_malloc_cb_backup = mem_malloc_cb;
        mem_malloc_cb = s2n_mem_test_malloc_cb;
    }
    if (mem_free_cb != s2n_mem_test_free_cb) {
        s2n_mem_free_cb_backup = mem_free_cb;
        mem_free_cb = s2n_mem_test_free_cb;
    }

    RESULT_GUARD(s2n_mem_override_callbacks(mem_init_cb, mem_cleanup_cb, mem_malloc_cb, mem_free_cb));

    return S2N_RESULT_OK;
}

static S2N_RESULT s2n_mem_test_unset_callbacks()
{
    s2n_mem_init_callback mem_init_cb = NULL;
    s2n_mem_cleanup_callback mem_cleanup_cb = NULL;
    s2n_mem_malloc_callback mem_malloc_cb = NULL;
    s2n_mem_free_callback mem_free_cb = NULL;
    RESULT_GUARD(s2n_mem_get_callbacks(&mem_init_cb, &mem_cleanup_cb, &mem_malloc_cb, &mem_free_cb));

    if (s2n_mem_malloc_cb_backup != NULL) {
        mem_malloc_cb = s2n_mem_malloc_cb_backup;
    }
    if (s2n_mem_free_cb_backup != NULL) {
        mem_free_cb = s2n_mem_free_cb_backup;
    }

    RESULT_GUARD(s2n_mem_override_callbacks(mem_init_cb, mem_cleanup_cb, mem_malloc_cb, mem_free_cb));

    return S2N_RESULT_OK;
}

static int s2n_mem_test_malloc_cb(void **ptr, uint32_t requested, uint32_t *allocated)
{
    int result = s2n_mem_malloc_cb_backup(ptr, requested, allocated);
    POSIX_GUARD(result);

    struct s2n_mem_test_malloc new_info = {
        .requested = requested,
        .ptr = *ptr,
        .allocated = *allocated,
        .freed = false,
    };

    POSIX_GUARD_RESULT(s2n_mem_test_unset_callbacks());
    POSIX_GUARD(s2n_stuffer_write_bytes(&s2n_mem_test_ctx.mallocs,
            (uint8_t *) &new_info, sizeof(new_info)));
    POSIX_GUARD_RESULT(s2n_mem_test_set_callbacks());

    return result;
}

static int s2n_mem_test_free_cb(void *ptr, uint32_t size)
{
    int result = s2n_mem_free_cb_backup(ptr, size);
    POSIX_GUARD(result);

    struct s2n_stuffer read_copy = s2n_mem_test_ctx.mallocs;
    while (s2n_stuffer_data_available(&read_copy)) {
        uint8_t *mem = s2n_stuffer_raw_read(&read_copy, sizeof(struct s2n_mem_test_malloc));
        struct s2n_mem_test_malloc *info = (struct s2n_mem_test_malloc *) (void *) mem;
        if (info->ptr == ptr) {
            info->freed = true;
        }
    }
    return result;
}

S2N_RESULT s2n_mem_test_init_callbacks(void *ctx)
{
    RESULT_GUARD(s2n_mem_test_free_callbacks(ctx));
    RESULT_GUARD_POSIX(s2n_stuffer_growable_alloc(&s2n_mem_test_ctx.mallocs, 0));
    RESULT_GUARD(s2n_mem_test_set_callbacks());
    return S2N_RESULT_OK;
}

S2N_CLEANUP_RESULT s2n_mem_test_free_callbacks(void *ctx)
{
    (void) ctx;
    RESULT_GUARD(s2n_mem_test_unset_callbacks());
    RESULT_GUARD_POSIX(s2n_stuffer_free(&s2n_mem_test_ctx.mallocs));
    return S2N_RESULT_OK;
}

S2N_RESULT s2n_mem_test_wipe_callbacks()
{
    RESULT_GUARD_POSIX(s2n_stuffer_wipe(&s2n_mem_test_ctx.mallocs));
    return S2N_RESULT_OK;
}

static S2N_RESULT s2n_mem_test_get_malloc_count(uint32_t *count)
{
    RESULT_ENSURE_REF(count);
    size_t size = s2n_stuffer_data_available(&s2n_mem_test_ctx.mallocs);
    const size_t sizeof_malloc = sizeof(struct s2n_mem_test_malloc);
    *count = size / sizeof_malloc;
    RESULT_ENSURE_EQ(size % sizeof_malloc, 0);
    return S2N_RESULT_OK;
}

static S2N_RESULT s2n_mem_test_get_malloc(uint32_t idx, struct s2n_mem_test_malloc *info)
{
    RESULT_ENSURE_REF(info);
    struct s2n_stuffer read_copy = s2n_mem_test_ctx.mallocs;
    const size_t sizeof_malloc = sizeof(struct s2n_mem_test_malloc);
    RESULT_GUARD_POSIX(s2n_stuffer_skip_read(&read_copy, idx * sizeof_malloc));
    RESULT_GUARD_POSIX(s2n_stuffer_read_bytes(&read_copy, (uint8_t *) info, sizeof_malloc));
    return S2N_RESULT_OK;
}

S2N_RESULT s2n_mem_test_assert_malloc_count(uint32_t count)
{
    uint32_t actual_count = 0;
    RESULT_GUARD(s2n_mem_test_get_malloc_count(&actual_count));
    RESULT_ENSURE(count == actual_count, S2N_ERR_TEST_ASSERTION);
    return S2N_RESULT_OK;
}

S2N_RESULT s2n_mem_test_assert_malloc(uint32_t requested)
{
    uint32_t count = 0;
    RESULT_GUARD(s2n_mem_test_get_malloc_count(&count));

    struct s2n_mem_test_malloc mem_info = { 0 };
    for (size_t i = 0; i < count; i++) {
        RESULT_GUARD(s2n_mem_test_get_malloc(i, &mem_info));
        if (mem_info.requested == requested) {
            return S2N_RESULT_OK;
        }
    }
    RESULT_BAIL(S2N_ERR_TEST_ASSERTION);
}

S2N_RESULT s2n_mem_test_assert_all_freed()
{
    uint32_t count = 0;
    RESULT_GUARD(s2n_mem_test_get_malloc_count(&count));

    struct s2n_mem_test_malloc mem_info = { 0 };
    for (size_t i = 0; i < count; i++) {
        RESULT_GUARD(s2n_mem_test_get_malloc(i, &mem_info));
        RESULT_ENSURE(mem_info.freed, S2N_ERR_TEST_ASSERTION);
    }
    return S2N_RESULT_OK;
}
