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

    /* Initialize s2n on a child thread and cleanup s2n on the original thread */
    {
        pthread_t init_thread = { 0 };
        EXPECT_EQUAL(pthread_create(&init_thread, NULL, s2n_initialize_thread_cb, NULL), 0);
        EXPECT_EQUAL(pthread_join(init_thread, NULL), 0);

        EXPECT_SUCCESS(s2n_cleanup());
    }
}
