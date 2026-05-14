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

#include <pthread.h>

#include "s2n_test.h"
#include "utils/s2n_mem.h"
#include "utils/s2n_safety.h"

bool s2n_is_initialized(void);

static void *s2n_init_fail_cb(void *_unused_arg)
{
    (void) _unused_arg;

    EXPECT_FAILURE_WITH_ERRNO(s2n_init(), S2N_ERR_INITIALIZED);
    return NULL;
}

static void *s2n_init_success_cb(void *_unused_arg)
{
    (void) _unused_arg;

    EXPECT_SUCCESS(s2n_init());
    return NULL;
}

/* Sentinel memory callbacks used by the cleanup/init regression test below.
 * They are never actually invoked for allocation or free: the test only
 * checks whether s2n_init() replaces them after the cleanup/init cycle.
 */
static int s2n_mem_sentinel_malloc_cb(void **ptr, uint32_t requested, uint32_t *allocated)
{
    (void) ptr;
    (void) requested;
    (void) allocated;
    return S2N_FAILURE;
}

static int s2n_mem_sentinel_free_cb(void *ptr, uint32_t size)
{
    (void) ptr;
    (void) size;
    return S2N_SUCCESS;
}

int main(int argc, char **argv)
{
    BEGIN_TEST_NO_INIT();

    /* Calling s2n_init twice in a row will cause an error */
    EXPECT_SUCCESS(s2n_init());
    EXPECT_FAILURE_WITH_ERRNO(s2n_init(), S2N_ERR_INITIALIZED);
    EXPECT_SUCCESS(s2n_cleanup_final());

    /* Second call to s2n_cleanup_final will fail, since the full cleanup is not idempotent. */
    EXPECT_FAILURE_WITH_ERRNO(s2n_cleanup_final(), S2N_ERR_NOT_INITIALIZED);

    /* Clean up and init multiple times */
    for (size_t i = 0; i < 10; i++) {
        EXPECT_SUCCESS(s2n_init());
        EXPECT_SUCCESS(s2n_cleanup_final());
    }

    /* Calling s2n_init again after creating a process will cause an error */
    EXPECT_SUCCESS(s2n_init());
    int pid = fork();
    if (pid == 0) {
        /* Child process */
        EXPECT_FAILURE_WITH_ERRNO(s2n_init(), S2N_ERR_INITIALIZED);
        return 0;
    }
    EXPECT_SUCCESS(s2n_cleanup_final());

    /* Calling s2n_init again after creating a thread will cause an error */
    EXPECT_SUCCESS(s2n_init());
    pthread_t init_thread = { 0 };
    EXPECT_EQUAL(pthread_create(&init_thread, NULL, s2n_init_fail_cb, NULL), 0);
    EXPECT_EQUAL(pthread_join(init_thread, NULL), 0);
    EXPECT_SUCCESS(s2n_cleanup_final());

    /* s2n_cleanup_final fully de-initializes the library */
    EXPECT_SUCCESS(s2n_init());
    EXPECT_TRUE(s2n_is_initialized());
    EXPECT_SUCCESS(s2n_cleanup_final());
    EXPECT_FALSE(s2n_is_initialized());

    /* The following test requires atexit to be enabled. */
    EXPECT_SUCCESS(s2n_enable_atexit());

    /* Initializing s2n on a child thread without calling s2n_cleanup on that
     * thread will not result in a memory leak. This is because we register
     * thread-local memory to be cleaned up at thread-exit. */
    pthread_t init_success_thread = { 0 };
    EXPECT_EQUAL(pthread_create(&init_success_thread, NULL, s2n_init_success_cb, NULL), 0);
    EXPECT_EQUAL(pthread_join(init_success_thread, NULL), 0);

    /* s2n_mem_init() restores the default memory callbacks across a
     * cleanup/init cycle.
     *
     * Regression test for the mlock/MADV_DONTDUMP hardening regression:
     * s2n_mem_cleanup_impl() switches the malloc/free callbacks to the
     * no-mlock variants as part of teardown. Prior to the fix, s2n_mem_init_impl()
     * only overwrote the callbacks when running in a unit test or when
     * S2N_DONT_MLOCK was set, so a cleanup_final()/init() cycle in a normal
     * production process permanently dropped the page-aligned + mlock +
     * MADV_DONTDUMP hardening for every subsequent key/secret allocation.
     *
     * This test installs a distinctive sentinel callback, simulates a
     * non-unit-test environment, cycles s2n_mem_cleanup()/s2n_mem_init()
     * directly (to isolate the path being tested from other init allocations
     * that would actually attempt to mlock), and verifies that init resets
     * the callbacks away from the sentinel — which it can only do if init
     * unconditionally restores the defaults.
     */
    {
        /* The lib is currently initialized (the previous atexit thread test
         * left it initialized). Proceed directly with the regression check.
         */

        /* Save the current callbacks so we can restore them at the end. */
        s2n_mem_init_callback saved_init_cb = NULL;
        s2n_mem_cleanup_callback saved_cleanup_cb = NULL;
        s2n_mem_malloc_callback saved_malloc_cb = NULL;
        s2n_mem_free_callback saved_free_cb = NULL;
        EXPECT_OK(s2n_mem_get_callbacks(&saved_init_cb, &saved_cleanup_cb,
                &saved_malloc_cb, &saved_free_cb));

        /* Ensure S2N_DONT_MLOCK is unset so the init path does not take
         * the "force no-mlock" branch.
         */
        EXPECT_EQUAL(unsetenv("S2N_DONT_MLOCK"), 0);

        /* Override the malloc/free callbacks with distinctive sentinel values.
         * These sentinels are never invoked; the test only observes whether
         * s2n_mem_init_impl() replaces them during the cycle below.
         */
        EXPECT_OK(s2n_mem_override_callbacks(saved_init_cb, saved_cleanup_cb,
                s2n_mem_sentinel_malloc_cb, s2n_mem_sentinel_free_cb));

        /* Verify the override took effect. */
        s2n_mem_malloc_callback observed_malloc_cb = NULL;
        s2n_mem_free_callback observed_free_cb = NULL;
        s2n_mem_init_callback ignored_init_cb = NULL;
        s2n_mem_cleanup_callback ignored_cleanup_cb = NULL;
        EXPECT_OK(s2n_mem_get_callbacks(&ignored_init_cb, &ignored_cleanup_cb,
                &observed_malloc_cb, &observed_free_cb));
        EXPECT_EQUAL(observed_malloc_cb, s2n_mem_sentinel_malloc_cb);
        EXPECT_EQUAL(observed_free_cb, s2n_mem_sentinel_free_cb);

        /* Simulate a non-unit-test environment across the cycle.
         * Without this, s2n_mem_init_impl() always takes the unit-test branch
         * and unconditionally sets the no-mlock callbacks, which would mask
         * the regression this test is guarding against.
         */
        EXPECT_SUCCESS(s2n_in_unit_test_set(false));

        /* Cycle the memory subsystem directly. Using s2n_mem_cleanup()/
         * s2n_mem_init() rather than s2n_cleanup_final()/s2n_init() avoids
         * triggering real mlock-backed allocations elsewhere in init, which
         * could fail under restrictive RLIMIT_MEMLOCK in CI environments.
         */
        EXPECT_SUCCESS(s2n_mem_cleanup());
        EXPECT_SUCCESS(s2n_mem_init());

        /* The regression check: after init, the callbacks must not be our
         * sentinel values. If they are, s2n_mem_init_impl() failed to restore
         * the hardened mlock defaults, and every subsequent key/secret
         * allocation would silently skip mlock and MADV_DONTDUMP hardening.
         */
        EXPECT_OK(s2n_mem_get_callbacks(&ignored_init_cb, &ignored_cleanup_cb,
                &observed_malloc_cb, &observed_free_cb));
        EXPECT_NOT_EQUAL(observed_malloc_cb, s2n_mem_sentinel_malloc_cb);
        EXPECT_NOT_EQUAL(observed_free_cb, s2n_mem_sentinel_free_cb);

        /* Restore unit-test mode and the original callbacks so the lib can
         * tear down cleanly with the no-mlock callbacks it started with.
         */
        EXPECT_SUCCESS(s2n_in_unit_test_set(true));
        EXPECT_OK(s2n_mem_override_callbacks(saved_init_cb, saved_cleanup_cb,
                saved_malloc_cb, saved_free_cb));
        EXPECT_SUCCESS(s2n_cleanup_final());
    };

    END_TEST_NO_INIT();
}
