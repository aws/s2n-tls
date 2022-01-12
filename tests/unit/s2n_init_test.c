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

    /* clean up and init multiple times */
    for (size_t i = 0; i < 10; i++) {
        s2n_cleanup();
        EXPECT_SUCCESS(s2n_init());
    }

    END_TEST();
}
