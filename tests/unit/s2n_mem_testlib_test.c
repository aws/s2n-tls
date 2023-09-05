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

#include "s2n_test.h"

int main()
{
    BEGIN_TEST();

    /* Test: No mallocs */
    for (size_t init = 0; init < 2; init++) {
        /* The getters and asserts should behave the same whether the callbacks
         * were never invoked or never initialized at all
         */
        if (init) {
            DEFER_CLEANUP(struct s2n_mem_test_cb_scope scope = { 0 },
                    s2n_mem_test_free_callbacks);
            EXPECT_OK(s2n_mem_test_init_callbacks(&scope));
        }

        /* Test: s2n_mem_test_assert_malloc_count */
        {
            EXPECT_OK(s2n_mem_test_assert_malloc_count(0));
            EXPECT_ERROR_WITH_ERRNO(s2n_mem_test_assert_malloc_count(1),
                    S2N_ERR_TEST_ASSERTION);
        };

        /* Test: s2n_mem_test_assert_malloc */
        {
            EXPECT_ERROR_WITH_ERRNO(s2n_mem_test_assert_malloc(0), S2N_ERR_TEST_ASSERTION);
            EXPECT_ERROR_WITH_ERRNO(s2n_mem_test_assert_malloc(1), S2N_ERR_TEST_ASSERTION);
            EXPECT_ERROR_WITH_ERRNO(s2n_mem_test_assert_malloc(UINT32_MAX),
                    S2N_ERR_TEST_ASSERTION);
        };

        /* Test: s2n_mem_test_assert_all_freed */
        EXPECT_OK(s2n_mem_test_assert_all_freed());
    };

    /* Test: Single malloc */
    {
        DEFER_CLEANUP(struct s2n_mem_test_cb_scope scope = { 0 },
                s2n_mem_test_free_callbacks);
        EXPECT_OK(s2n_mem_test_init_callbacks(&scope));

        const size_t requested = 17;
        struct s2n_blob mem = { 0 };
        EXPECT_SUCCESS(s2n_alloc(&mem, requested));
        EXPECT_NOT_NULL(mem.data);
        EXPECT_EQUAL(mem.size, requested);

        /* Test: s2n_mem_test_assert_malloc_count */
        {
            EXPECT_OK(s2n_mem_test_assert_malloc_count(1));
            EXPECT_ERROR_WITH_ERRNO(s2n_mem_test_assert_malloc_count(0),
                    S2N_ERR_TEST_ASSERTION);
            EXPECT_ERROR_WITH_ERRNO(s2n_mem_test_assert_malloc_count(2),
                    S2N_ERR_TEST_ASSERTION);
        };

        /* Test: s2n_mem_test_assert_malloc */
        {
            EXPECT_OK(s2n_mem_test_assert_malloc(requested));
            EXPECT_ERROR_WITH_ERRNO(s2n_mem_test_assert_malloc(0), S2N_ERR_TEST_ASSERTION);
            EXPECT_ERROR_WITH_ERRNO(s2n_mem_test_assert_malloc(1), S2N_ERR_TEST_ASSERTION);
            EXPECT_ERROR_WITH_ERRNO(s2n_mem_test_assert_malloc(UINT32_MAX),
                    S2N_ERR_TEST_ASSERTION);
        };

        /* Test: s2n_mem_test_assert_all_freed */
        {
            EXPECT_ERROR_WITH_ERRNO(s2n_mem_test_assert_all_freed(), S2N_ERR_TEST_ASSERTION);
            EXPECT_SUCCESS(s2n_free(&mem));
            EXPECT_OK(s2n_mem_test_assert_all_freed());
        };
    };

    /* Test: Multiple mallocs */
    {
        DEFER_CLEANUP(struct s2n_mem_test_cb_scope scope = { 0 },
                s2n_mem_test_free_callbacks);
        EXPECT_OK(s2n_mem_test_init_callbacks(&scope));

        const size_t requested[] = { 10, 1, 17, 17, 111 };
        const size_t count = s2n_array_len(requested);
        struct s2n_blob mem = { 0 };
        for (size_t i = 0; i < count; i++) {
            EXPECT_SUCCESS(s2n_alloc(&mem, requested[i]));
            EXPECT_NOT_NULL(mem.data);
            EXPECT_EQUAL(mem.size, requested[i]);
            EXPECT_SUCCESS(s2n_free(&mem));
        }

        /* Test: s2n_mem_test_assert_malloc_count */
        {
            EXPECT_OK(s2n_mem_test_assert_malloc_count(count));
            EXPECT_ERROR_WITH_ERRNO(s2n_mem_test_assert_malloc_count(0),
                    S2N_ERR_TEST_ASSERTION);
            EXPECT_ERROR_WITH_ERRNO(s2n_mem_test_assert_malloc_count(count - 1),
                    S2N_ERR_TEST_ASSERTION);
            EXPECT_ERROR_WITH_ERRNO(s2n_mem_test_assert_malloc_count(count + 1),
                    S2N_ERR_TEST_ASSERTION);
        };

        /* Test: s2n_mem_test_assert_malloc */
        {
            for (size_t i = 0; i < count; i++) {
                EXPECT_OK(s2n_mem_test_assert_malloc(requested[i]));
            }
            EXPECT_ERROR_WITH_ERRNO(s2n_mem_test_assert_malloc(0), S2N_ERR_TEST_ASSERTION);
            EXPECT_ERROR_WITH_ERRNO(s2n_mem_test_assert_malloc(UINT32_MAX),
                    S2N_ERR_TEST_ASSERTION);
        };

        /* Test: s2n_mem_test_assert_all_freed */
        {
            EXPECT_OK(s2n_mem_test_assert_all_freed());
            EXPECT_SUCCESS(s2n_alloc(&mem, 1));
            EXPECT_ERROR_WITH_ERRNO(s2n_mem_test_assert_all_freed(), S2N_ERR_TEST_ASSERTION);
            EXPECT_SUCCESS(s2n_free(&mem));
            EXPECT_OK(s2n_mem_test_assert_all_freed());
        };
    };

    /* Test: s2n_mem_test_wipe_callbacks */
    {
        DEFER_CLEANUP(struct s2n_mem_test_cb_scope scope = { 0 },
                s2n_mem_test_free_callbacks);
        EXPECT_OK(s2n_mem_test_init_callbacks(&scope));

        DEFER_CLEANUP(struct s2n_blob mem = { 0 }, s2n_free);
        EXPECT_SUCCESS(s2n_alloc(&mem, 1));
        EXPECT_NOT_NULL(mem.data);
        EXPECT_OK(s2n_mem_test_assert_malloc_count(1));

        EXPECT_OK(s2n_mem_test_wipe_callbacks());
        EXPECT_OK(s2n_mem_test_assert_malloc_count(0));
    };

    /* Test: s2n_mem_test_init_callbacks */
    {
        EXPECT_OK(s2n_mem_test_init_callbacks(NULL));
        for (size_t i = 0; i < 5; i++) {
            DEFER_CLEANUP(struct s2n_blob mem = { 0 }, s2n_free);
            EXPECT_SUCCESS(s2n_alloc(&mem, 1));
            EXPECT_NOT_NULL(mem.data);
            EXPECT_OK(s2n_mem_test_assert_malloc_count(1));

            /* If already initialized, we just wipe the state */
            EXPECT_OK(s2n_mem_test_init_callbacks(NULL));
            EXPECT_OK(s2n_mem_test_assert_malloc_count(0));
        }
        EXPECT_OK(s2n_mem_test_free_callbacks(NULL));
    };

    /* Test: s2n_mem_test_free_callbacks */
    {
        for (size_t i = 1; i < 5; i++) {
            EXPECT_OK(s2n_mem_test_free_callbacks(NULL));

            DEFER_CLEANUP(struct s2n_blob mem = { 0 }, s2n_free);
            EXPECT_SUCCESS(s2n_alloc(&mem, 1));
            EXPECT_NOT_NULL(mem.data);
            EXPECT_OK(s2n_mem_test_assert_malloc_count(0));
        }

        EXPECT_OK(s2n_mem_test_init_callbacks(NULL));
        DEFER_CLEANUP(struct s2n_blob mem = { 0 }, s2n_free);
        EXPECT_SUCCESS(s2n_alloc(&mem, 1));
        EXPECT_OK(s2n_mem_test_assert_malloc_count(1));

        for (size_t i = 1; i < 5; i++) {
            EXPECT_OK(s2n_mem_test_free_callbacks(NULL));
            EXPECT_OK(s2n_mem_test_assert_malloc_count(0));

            DEFER_CLEANUP(struct s2n_blob mem2 = { 0 }, s2n_free);
            EXPECT_SUCCESS(s2n_alloc(&mem2, 1));
            EXPECT_NOT_NULL(mem2.data);
            EXPECT_OK(s2n_mem_test_assert_malloc_count(0));
        }
    };

    END_TEST();
}
