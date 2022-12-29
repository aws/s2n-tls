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

#include "crypto/s2n_locking.h"

#include <pthread.h>

#include "s2n_test.h"

#define LOCK_N 1

#if !(S2N_OPENSSL_VERSION_AT_LEAST(1, 1, 0))

static void *s2n_test_thread(void *arg)
{
    bool *lock_was_acquired = (bool *) arg;
    CRYPTO_lock(CRYPTO_LOCK, LOCK_N, NULL, 0);
    *lock_was_acquired = true;
    CRYPTO_lock(CRYPTO_UNLOCK, LOCK_N, NULL, 0);
    return NULL;
}

static void s2n_test_locking_cb(int mode, int n, char *file, int line)
{
    return;
}

int main(int argc, char **argv)
{
    BEGIN_TEST();

    /* Test: libcrypto locks should actually lock.
     *
     * If libcrypto locking is not configured properly, then
     * libcrypto locks will be no-ops and will not block threads.
     */
    {
        /* Lock one of the libcrypto locks */
        CRYPTO_lock(CRYPTO_LOCK, LOCK_N, NULL, 0);

        /* Create a new thread which will try to take the lock held by this thread
         * in order to set a flag.
         */
        bool lock_was_acquired = false;
        pthread_t thread = { 0 };
        EXPECT_EQUAL(pthread_create(&thread, NULL, s2n_test_thread, &lock_was_acquired), 0);

        /* Expect the flag NOT to be set because we still hold the lock */
        sleep(1);
        EXPECT_FALSE(lock_was_acquired);

        /* Release the libcrypto lock */
        CRYPTO_lock(CRYPTO_UNLOCK, LOCK_N, NULL, 0);

        /* Expect the flag to be set because the new thread took the lock */
        void *retval = NULL;
        EXPECT_EQUAL(pthread_join(thread, &retval), 0);
        EXPECT_TRUE(lock_was_acquired);
    };

    /* Test: basic lifecycle */
    {
        EXPECT_OK(s2n_locking_cleanup());
        EXPECT_OK(s2n_locking_init());
    };

    /* Test: s2n-tls should not override locking configured by the application */
    {
        /* The callback should have already been set by BEGIN_TEST()
         * or a later call to s2n_locking_init().
         */
        EXPECT_NOT_EQUAL(CRYPTO_get_locking_callback(), NULL);

        /* Manually override the existing callback.
         * Applications might set their callback after calling s2n_init.
         */
        CRYPTO_set_locking_callback((void (*)()) s2n_test_locking_cb);
        EXPECT_EQUAL(CRYPTO_get_locking_callback(), (void (*)()) s2n_test_locking_cb);

        /* Cleaning up does not affect the application-set callback */
        EXPECT_OK(s2n_locking_cleanup());
        EXPECT_EQUAL(CRYPTO_get_locking_callback(), (void (*)()) s2n_test_locking_cb);

        /* Initializing again doesn't override the application-set callback.
         * Applications might set their callback before calling s2n_init.
         */
        EXPECT_OK(s2n_locking_init());
        EXPECT_EQUAL(CRYPTO_get_locking_callback(), (void (*)()) s2n_test_locking_cb);
        EXPECT_OK(s2n_locking_cleanup());
        EXPECT_EQUAL(CRYPTO_get_locking_callback(), (void (*)()) s2n_test_locking_cb);

        /* Reset the callback */
        CRYPTO_set_locking_callback(NULL);
        EXPECT_EQUAL(CRYPTO_get_locking_callback(), NULL);

        /* Initializing now sets the missing callback */
        EXPECT_OK(s2n_locking_init());
        EXPECT_NOT_EQUAL(CRYPTO_get_locking_callback(), NULL);
    };

    END_TEST();
}

#else

int main(int argc, char **argv)
{
    BEGIN_TEST();
    END_TEST();
}

#endif
