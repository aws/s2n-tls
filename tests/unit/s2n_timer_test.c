/*
 * Copyright 2015 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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
#include <unistd.h>

#include "s2n_test.h"

#include "utils/s2n_timer.h"

int main(int argc, char **argv)
{
    struct s2n_timer timer;
    uint64_t nanoseconds;

    BEGIN_TEST();

    EXPECT_SUCCESS(s2n_timer_start(&timer));
    EXPECT_SUCCESS(s2n_timer_reset(&timer, &nanoseconds));
    EXPECT_TRUE(nanoseconds < 1000000000);
    EXPECT_SUCCESS(sleep(1));
    EXPECT_SUCCESS(s2n_timer_reset(&timer, &nanoseconds));
    EXPECT_TRUE(nanoseconds > 1000000000);

    END_TEST();
}
