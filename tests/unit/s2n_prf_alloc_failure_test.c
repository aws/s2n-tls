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
#include "s2n_test.h"
#include "testlib/s2n_testlib.h"
#include "tls/s2n_connection.h"
#include "tls/s2n_prf.h"
#include "utils/s2n_mem.h"
#include "utils/s2n_safety.h"

/*
 * Tests that if workspace allocation fails, s2n_connection_get_prf_space returns
 * a clean error without crashing, leaking, or dereferencing unallocated memory.
 * Verifies the allocation is recoverable on retry.
 */

/* A malloc callback that fails on the Nth invocation (1-indexed) and succeeds
 * (delegating to the real allocator) on all others. This lets us target a
 * specific s2n allocation rather than globally breaking the allocator.
 */
static s2n_mem_malloc_callback s2n_real_malloc_cb = NULL;
static uint32_t s2n_malloc_call_count = 0;
static uint32_t s2n_malloc_fail_on_call = 0;

static int s2n_nth_call_failing_malloc_cb(void **ptr, uint32_t requested, uint32_t *allocated)
{
    s2n_malloc_call_count++;
    if (s2n_malloc_call_count == s2n_malloc_fail_on_call) {
        *ptr = NULL;
        *allocated = 0;
        POSIX_BAIL(S2N_ERR_ALLOC);
    }
    return s2n_real_malloc_cb(ptr, requested, allocated);
}

int main(int argc, char **argv)
{
    BEGIN_TEST();

    /* Capture the real callbacks installed by s2n_init() so our wrapper can
     * delegate to them and so we can always restore them.
     */
    s2n_mem_init_callback init_cb = NULL;
    s2n_mem_cleanup_callback cleanup_cb = NULL;
    s2n_mem_malloc_callback malloc_cb = NULL;
    s2n_mem_free_callback free_cb = NULL;
    EXPECT_OK(s2n_mem_get_callbacks(&init_cb, &cleanup_cb, &malloc_cb, &free_cb));
    s2n_real_malloc_cb = malloc_cb;

    /* The workspace allocation gates the reusable-context allocation, so failing
     * it is the s2n-injectable trigger for Requirement 4.6.
     *
     * s2n_prf_new() makes exactly one s2n_realloc() call (the workspace) before
     * touching any context field, so failing the first s2n malloc reaches the
     * derivation-context setup's outermost GUARD.
     */

    /* s2n_connection_get_prf_space: lazy-alloc workspace allocation failure
     * returns a clean error, leaves prf_space NULL (no dereference of the
     * unallocated tls13_hmac/tls13_hash), and is recoverable. */
    {
        DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_SERVER),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(conn);

        /* s2n_connection_new() eagerly allocates prf_space; free it so we drive
         * the lazy-allocation path that the TLS 1.3 derivation sites use. */
        EXPECT_OK(s2n_prf_free(conn));
        EXPECT_NULL(conn->prf_space);

        /* Fail the very next s2n allocation (the workspace realloc). */
        s2n_malloc_call_count = 0;
        s2n_malloc_fail_on_call = 1;
        EXPECT_OK(s2n_mem_override_callbacks(init_cb, cleanup_cb,
                s2n_nth_call_failing_malloc_cb, free_cb));

        struct s2n_prf_working_space *ws = NULL;
        EXPECT_ERROR_WITH_ERRNO(s2n_connection_get_prf_space(conn, &ws), S2N_ERR_ALLOC);

        /* Restore immediately so subsequent operations can allocate. */
        EXPECT_OK(s2n_mem_override_callbacks(init_cb, cleanup_cb, malloc_cb, free_cb));

        /* No dereference of an unallocated context: the out-param is untouched
         * and the workspace pointer is still NULL (never partially populated). */
        EXPECT_NULL(ws);
        EXPECT_NULL(conn->prf_space);

        /* Exactly one s2n allocation was attempted before the clean bail. */
        EXPECT_EQUAL(s2n_malloc_call_count, 1);

        /* Recoverable: with the real allocator restored, the workspace (and its
         * reusable contexts) allocates successfully. */
        EXPECT_OK(s2n_connection_get_prf_space(conn, &ws));
        EXPECT_NOT_NULL(ws);
        EXPECT_EQUAL(ws, conn->prf_space);

        /* DEFER_CLEANUP frees the connection here; under valgrind/ASAN this
         * confirms no leak from either the failed or the successful path. */
    };

    /* s2n_prf_new: direct workspace allocation failure path. */
    {
        DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_SERVER),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(conn);

        EXPECT_OK(s2n_prf_free(conn));
        EXPECT_NULL(conn->prf_space);

        s2n_malloc_call_count = 0;
        s2n_malloc_fail_on_call = 1;
        EXPECT_OK(s2n_mem_override_callbacks(init_cb, cleanup_cb,
                s2n_nth_call_failing_malloc_cb, free_cb));

        EXPECT_ERROR_WITH_ERRNO(s2n_prf_new(conn), S2N_ERR_ALLOC);

        EXPECT_OK(s2n_mem_override_callbacks(init_cb, cleanup_cb, malloc_cb, free_cb));

        /* On failure prf_space must be NULL, never half-initialized. */
        EXPECT_NULL(conn->prf_space);

        /* s2n_prf_free must be safe to call on the NULL/failed workspace
         * (no crash, no double-free, no dereference of unallocated context). */
        EXPECT_OK(s2n_prf_free(conn));
        EXPECT_NULL(conn->prf_space);
    };

    END_TEST();
}
