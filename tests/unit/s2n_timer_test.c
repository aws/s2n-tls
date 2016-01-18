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
#include "s2n_test.h"

#include "utils/s2n_timer.h"

int main(int argc, char **argv)
{
    struct s2n_timer timer;
    uint64_t nanoseconds;

    BEGIN_TEST();

    /* First: Perform some tests using the real clock */
    EXPECT_SUCCESS(s2n_timer_start(&timer));
    EXPECT_SUCCESS(s2n_timer_reset(&timer, &nanoseconds));
    EXPECT_TRUE(nanoseconds < 1000000000);
    EXPECT_SUCCESS(s2n_timer_elapsed(&timer, &nanoseconds));
    EXPECT_TRUE(nanoseconds < 1000000000);
    EXPECT_SUCCESS(sleep(1));
    EXPECT_SUCCESS(s2n_timer_reset(&timer, &nanoseconds));
    EXPECT_TRUE(nanoseconds > 1000000000);
    EXPECT_TRUE(nanoseconds < 2000000000);
    EXPECT_SUCCESS(sleep(1));
    EXPECT_SUCCESS(s2n_timer_elapsed(&timer, &nanoseconds));
    EXPECT_TRUE(nanoseconds > 1000000000);
    EXPECT_TRUE(nanoseconds < 2000000000);

#if !defined(__APPLE__) || !defined(__MACH__)
    /* Next: perform some tests around timespec boundaries */

    /* Pretend that there were 999,999,999 nanoseconds elapsed in the
     * previously measured instant. Keep reseting the timer until
     * the second progresses from that instant, and there are also
     * less than 999,999,999 nanoseconds elapsed.
     *
     * This sets up a situation in which the tv_sec field causes time
     * to move "forwards", and tv_nsec causes it to move backwards.
     * e.g.
     *
     * previous_time = 10
     *
     * timer.time.tv_sec = 11
     * timer.time.tv_nsec = 123456789;
     *
     * delta will be:
     *   (11 - 10) * 1000000000
     * + (123456789 - 999999999)
     *
     * = 123456790 (same as 1 + 123456789)
     */
    time_t previous_time;
    do {
        previous_time = timer.time.tv_sec;
        timer.time.tv_nsec = 999999999;

        EXPECT_SUCCESS(s2n_timer_reset(&timer, &nanoseconds));
    }
    while(previous_time != (timer.time.tv_sec - 1) || timer.time.tv_nsec == 999999999);

    EXPECT_TRUE(nanoseconds < 1000000000);
    EXPECT_TRUE(nanoseconds == 1 + timer.time.tv_nsec);

    /* Now we perform the oppossite test: make sure that the previous value for
     * nsec is smaller than the later one */
    do {
        previous_time = timer.time.tv_sec;
        timer.time.tv_nsec = 0;

        EXPECT_SUCCESS(s2n_timer_reset(&timer, &nanoseconds));
    }
    while(previous_time != (timer.time.tv_sec - 1) || timer.time.tv_nsec == 0);

    EXPECT_TRUE(nanoseconds > 1000000000);
    EXPECT_TRUE(nanoseconds < 2000000000);
    EXPECT_TRUE(nanoseconds == 1000000000 + timer.time.tv_nsec);
#endif

    END_TEST();
}
