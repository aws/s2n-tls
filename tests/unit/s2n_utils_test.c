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
#include "testlib/s2n_testlib.h"
#include "utils/s2n_blob.h"
#include "utils/s2n_safety.h"

#define test_stack_blob_success(test_name, macro_name, requested, max) \
    int test_name()                                                    \
    {                                                                  \
        macro_name(test_name##blob, requested, max);                   \
        POSIX_ENSURE_EQ(test_name##blob.size, requested);              \
        return 0;                                                      \
    }

test_stack_blob_success(success_equal, s2n_stack_blob, 10, 10)

test_stack_blob_success(success_equal_smaller, s2n_stack_blob, 10, 100)

int requested_bigger_than_max()
{
    s2n_stack_blob(foo, 11, 10);
    /* This should never be reached due to the above failure */
    POSIX_ENSURE_EQ(foo.allocated, 0);

    return 0;
}

int successful_stack_blob()
{
    s2n_stack_blob(foo, 10, 10);
    POSIX_ENSURE_EQ(foo.size, 10);
    POSIX_ENSURE_EQ(foo.allocated, 0);

    s2n_stack_blob(foo2, 1, 10);
    POSIX_ENSURE_EQ(foo2.size, 1);
    POSIX_ENSURE_EQ(foo2.allocated, 0);

    return 0;
}

int main(int argc, char **argv)
{
    BEGIN_TEST();
    EXPECT_SUCCESS(s2n_disable_tls13_in_test());
    EXPECT_FAILURE(requested_bigger_than_max());
    EXPECT_SUCCESS(successful_stack_blob());
    END_TEST();
}
