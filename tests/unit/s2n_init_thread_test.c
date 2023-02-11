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

static void *s2n_initialize_thread_cb(void *_unused_arg)
{
    (void) _unused_arg;

    EXPECT_SUCCESS(s2n_init());
    return NULL;
}

int main(int argc, char **argv)
{
    BEGIN_TEST_NO_INIT();

    /* Tests our thread-local memory cleanup. 
     *
     * Initializing s2n on a child thread without calling s2n_cleanup on that 
     * thread will not result in a memory leak. This is because we register 
     * thread-local memory to be cleaned up at thread-exit
     * and then our atexit handler cleans up the rest at proccess-exit. */
    {
        pthread_t init_thread = { 0 };
        EXPECT_EQUAL(pthread_create(&init_thread, NULL, s2n_initialize_thread_cb, NULL), 0);
        EXPECT_EQUAL(pthread_join(init_thread, NULL), 0);
    }

    END_TEST_NO_INIT();
}
