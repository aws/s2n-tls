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
#include "api/s2n.h"
#include "utils/s2n_random.h"

#include <pthread.h>

/**
 * This is an ASAN test which ensures that if s2n_init_drbgs() (via s2n_rand_init()) and
 * s2n_rand_cleanup_thread() are called from different threads, the thread-local memory
 * allocated in s2n_init_drbgs() will leak if no thread exit handler is configured.
 */
static void * s2n_drbg_thread_initialization_cb(void *_unused_arg)
{
    (void)_unused_arg;

    /* Called from a separate thread: */
    EXPECT_OK(s2n_rand_init());
    return NULL;
}

static S2N_RESULT s2n_drbg_thread_initialization(void) 
{
    pthread_t init_thread;

    EXPECT_EQUAL(pthread_create(&init_thread, NULL, s2n_drbg_thread_initialization_cb, NULL), 0);
    EXPECT_EQUAL(pthread_join(init_thread, NULL), 0);

    return S2N_RESULT_OK;
}

int main(int argc, char **argv)
{
    BEGIN_TEST_NO_INIT();

    EXPECT_OK(s2n_drbg_thread_initialization());
    /* s2n_rand_cleanup is called from main only. It has no effect on the thread-local allocations
     * made by s2n_init_drbgs() via s2n_rand_init() in the separate thread above.  */
    EXPECT_OK(s2n_rand_cleanup());

    END_TEST_NO_INIT();
}
