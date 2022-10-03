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

int main(int argc, char **argv)
{
    /* disable deferred cleanup */
    s2n_disable_atexit();

    /* this includes a call to s2n_init */
    BEGIN_TEST();

    /* test call idempotency: see https://github.com/aws/s2n-tls/issues/3446 */
    EXPECT_FAILURE_WITH_ERRNO(s2n_init(), S2N_ERR_INITIALIZED);

    /* cleanup can only be called once when atexit is disabled, since mem_cleanup is not idempotent */
    EXPECT_SUCCESS(s2n_cleanup());
    EXPECT_FAILURE_WITH_ERRNO(s2n_cleanup(), S2N_ERR_NOT_INITIALIZED);

    /* clean up and init multiple times */
    EXPECT_SUCCESS(s2n_init());
    for (size_t i = 0; i < 10; i++) {
        EXPECT_SUCCESS(s2n_cleanup());
        EXPECT_SUCCESS(s2n_init());
    }

    /* this includes a call to s2n_cleanup */
    END_TEST();
}
