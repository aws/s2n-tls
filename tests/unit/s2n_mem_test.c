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

#include "s2n_test.h"
#include "utils/s2n_safety.h"

/* Required to override memory callbacks at runtime */
#include "utils/s2n_mem.c"

int s2n_strict_mem_free_cb(void *ptr, uint32_t size)
{
    POSIX_ENSURE_REF(ptr);
    POSIX_ENSURE_GT(size, 0);
    return S2N_SUCCESS;
}

int main(int argc, char **argv)
{
    BEGIN_TEST();

    /* Test safety of all mem free methods */
    {
        /* Test: no-op for empty blob */
        {
            struct s2n_blob blob = { 0 };
            EXPECT_SUCCESS(s2n_free(&blob));
            EXPECT_SUCCESS(s2n_free_without_wipe(&blob));
            EXPECT_SUCCESS(s2n_free_or_wipe(&blob));
        };

        /* Test: no-op for already freed blob */
        {
            struct s2n_blob blob = { 0 };
            EXPECT_SUCCESS(s2n_alloc(&blob, 10));
            EXPECT_SUCCESS(s2n_free(&blob));

            EXPECT_SUCCESS(s2n_free(&blob));
            EXPECT_SUCCESS(s2n_free_without_wipe(&blob));
            EXPECT_SUCCESS(s2n_free_or_wipe(&blob));
        };

        /* Test: error for NULL */
        {
            EXPECT_FAILURE_WITH_ERRNO(s2n_free(NULL), S2N_ERR_NULL);
            EXPECT_FAILURE_WITH_ERRNO(s2n_free_without_wipe(NULL), S2N_ERR_NULL);
            EXPECT_FAILURE_WITH_ERRNO(s2n_free_or_wipe(NULL), S2N_ERR_NULL);
        };

        /* Test: faulty / overly strict free implementation
         *
         * A correct implementation of free() should be a no-op for a NULL pointer.
         * However, we have encountered cases where faulty implementations of free()
         * seg faulted on NULL: our Rust bindings initially incorrectly assumed that
         * Rust's dealloc() handled NULLs like C's free().
         *
         * As an easy way to avoid this, we should just never call the free mem callback for NULL.
         */
        {
            /* Save real free callback */
            s2n_mem_free_callback saved_free_cb = s2n_mem_free_cb;

            /* Set callback that won't accepts NULLs / zeros */
            s2n_mem_free_cb = s2n_strict_mem_free_cb;

            /* No-op for empty blob */
            struct s2n_blob blob = { 0 };
            EXPECT_SUCCESS(s2n_free(&blob));
            EXPECT_SUCCESS(s2n_free_without_wipe(&blob));
            EXPECT_SUCCESS(s2n_free_or_wipe(&blob));

            /* Restore real free callback */
            s2n_mem_free_cb = saved_free_cb;
        };
    };

    END_TEST();
}
