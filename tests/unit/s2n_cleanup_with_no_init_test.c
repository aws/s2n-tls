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

static int my_global;

static void my_destructor(void *arg) {}

/* Checks that calling s2n_cleanup without s2n_init does not corrupt
 * thread-local storage. */

int main(int argc, char **argv)
{
    BEGIN_TEST_NO_INIT();

    pthread_key_t my_key;

    /* Init the pthread key */
    EXPECT_SUCCESS(pthread_key_create(&my_key, my_destructor));

    /* Set it a value */
    EXPECT_SUCCESS(pthread_setspecific(my_key, &my_global));

    /* Call s2n_cleanup with no init */
    EXPECT_SUCCESS(s2n_cleanup());

    /* Check that the key is not corrupted */
    int *new_value = (int *) pthread_getspecific(my_key);
    EXPECT_EQUAL(new_value, &my_global);

    /* Delete the key */
    EXPECT_SUCCESS(pthread_key_delete(my_key));

    END_TEST_NO_INIT();
}
