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

#include "api/unstable/cleanup.h"
#include "s2n_test.h"

bool s2n_is_initialized(void);
int s2n_enable_atexit(void);

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

static void *s2n_cleanup_thread_cb(void *_unused_arg)
{
    (void) _unused_arg;

    EXPECT_SUCCESS(s2n_cleanup_thread());
    return NULL;
}

int main(int argc, char **argv)
{
    BEGIN_TEST_NO_INIT();

    /* Disabling the atexit handler makes it easier for us to test s2n_init and s2n_cleanup
     * behavior. Otherwise we'd have to create and exit a bunch of processes to test this
     * interaction. */
    EXPECT_SUCCESS(s2n_disable_atexit());

    /* Calling s2n_init twice in a row will cause an error */
    EXPECT_SUCCESS(s2n_init());
    EXPECT_FAILURE_WITH_ERRNO(s2n_init(), S2N_ERR_INITIALIZED);
    EXPECT_SUCCESS(s2n_cleanup());

    /* Second call to s2n_cleanup will fail, since the full cleanup is not idempotent.
     * This behavior only exists when atexit is disabled. */
    EXPECT_FAILURE_WITH_ERRNO(s2n_cleanup(), S2N_ERR_NOT_INITIALIZED);

    /* Clean up and init multiple times */
    for (size_t i = 0; i < 10; i++) {
        EXPECT_SUCCESS(s2n_init());
        EXPECT_SUCCESS(s2n_cleanup());
    }

    /* Calling s2n_init again after creating a process will cause an error */
    EXPECT_SUCCESS(s2n_init());
    int pid = fork();
    if (pid == 0) {
        /* Child process */
        EXPECT_FAILURE_WITH_ERRNO(s2n_init(), S2N_ERR_INITIALIZED);
        EXPECT_SUCCESS(s2n_cleanup());
        return 0;
    }
    EXPECT_SUCCESS(s2n_cleanup());

    /* Calling s2n_init again after creating a thread will cause an error */
    EXPECT_SUCCESS(s2n_init());
    pthread_t init_thread = { 0 };
    EXPECT_EQUAL(pthread_create(&init_thread, NULL, s2n_init_fail_cb, NULL), 0);
    EXPECT_EQUAL(pthread_join(init_thread, NULL), 0);
    EXPECT_SUCCESS(s2n_cleanup());

    /* Calling s2n_init/s2n_cleanup in a different thread than s2n_cleanup_thread is called cleans up properly */
    {
        EXPECT_SUCCESS(s2n_init());
        EXPECT_TRUE(s2n_is_initialized());
        pthread_t s2n_cleanup_th = { 0 };
        EXPECT_EQUAL(pthread_create(&s2n_cleanup_th, NULL, s2n_cleanup_thread_cb, NULL), 0);
        EXPECT_EQUAL(pthread_join(s2n_cleanup_th, NULL), 0);
        EXPECT_TRUE(s2n_is_initialized());
        /* Calling s2n_cleanup_thread in the main thread leaves s2n initialized. */
        EXPECT_SUCCESS(s2n_cleanup_thread());
        EXPECT_TRUE(s2n_is_initialized());
        EXPECT_SUCCESS(s2n_cleanup());
        EXPECT_FALSE(s2n_is_initialized());
        /* Second call to s2n_cleanup will fail, since the full cleanup is not idempotent. */
        EXPECT_FAILURE_WITH_ERRNO(s2n_cleanup(), S2N_ERR_NOT_INITIALIZED);
    }

    /* s2n_cleanup_final */
    {
        /* s2n_cleanup_final fully de-initializes the library */
        EXPECT_SUCCESS(s2n_init());
        EXPECT_TRUE(s2n_is_initialized());
        EXPECT_SUCCESS(s2n_cleanup_final());
        EXPECT_FALSE(s2n_is_initialized());

        /* s2n_cleanup fully cleans up the library when the atexit handler is disabled.
         * Therefore, calling s2n_cleanup_final after s2n_cleanup will error */
        EXPECT_SUCCESS(s2n_init());
        EXPECT_SUCCESS(s2n_cleanup());
        EXPECT_FAILURE_WITH_ERRNO(s2n_cleanup_final(), S2N_ERR_NOT_INITIALIZED);

        /* s2n_cleanup_thread only cleans up thread-local storage.
         * Therefore calling s2n_cleanup_final after s2n_cleanup_thread will succeed  */
        EXPECT_SUCCESS(s2n_init());
        EXPECT_SUCCESS(s2n_cleanup_thread());
        EXPECT_SUCCESS(s2n_cleanup_final());
    }

    /* The following test requires atexit to be enabled. */
    EXPECT_SUCCESS(s2n_enable_atexit());

    /* Initializing s2n on a child thread without calling s2n_cleanup on that
     * thread will not result in a memory leak. This is because we register
     * thread-local memory to be cleaned up at thread-exit
     * and then our atexit handler cleans up the rest at proccess-exit. */
    pthread_t init_success_thread = { 0 };
    EXPECT_EQUAL(pthread_create(&init_success_thread, NULL, s2n_init_success_cb, NULL), 0);
    EXPECT_EQUAL(pthread_join(init_success_thread, NULL), 0);

    END_TEST_NO_INIT();
}
