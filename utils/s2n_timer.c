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

#include "utils/s2n_safety.h"
#include "utils/s2n_timer.h"

#if defined(__APPLE__) && defined(__MACH__)
#include <mach/clock.h>
#include <mach/mach.h>
#include <mach/mach_time.h>

int s2n_timer_start(struct s2n_timer *timer) 
{
    timer->time = mach_absolute_time();

    return 0;
}

int s2n_timer_elapsed(struct s2n_timer *timer, uint64_t *nanoseconds)
{
    mach_timebase_info_data_t conversion_factor;
    uint64_t current_time = mach_absolute_time();

    *nanoseconds = current_time - timer->time;

    GUARD(mach_timebase_info(&conversion_factor));

    *nanoseconds *= conversion_factor.numer;
    *nanoseconds /= conversion_factor.denom;

    return 0;
}

int s2n_timer_reset(struct s2n_timer *timer, uint64_t *nanoseconds)
{
    mach_timebase_info_data_t conversion_factor;
    uint64_t previous_time = timer->time;

    GUARD(s2n_timer_start(timer));

    *nanoseconds = timer->time - previous_time;

    GUARD(mach_timebase_info(&conversion_factor));

    *nanoseconds *= conversion_factor.numer;
    *nanoseconds /= conversion_factor.denom;

    return 0;
}

#else

#if defined(CLOCK_MONOTONIC_RAW)
    #define S2N_CLOCK CLOCK_MONOTONIC_RAW
#else
    #define S2N_CLOCK CLOCK_MONOTONIC
#endif

int s2n_timer_start(struct s2n_timer *timer) 
{
    GUARD(clock_gettime(S2N_CLOCK, &timer->time));

    return 0;
}

int s2n_timer_elapsed(struct s2n_timer *timer, uint64_t *nanoseconds)
{
    struct timespec current_time;

    GUARD(clock_gettime(S2N_CLOCK, &current_time));

    *nanoseconds =  (current_time.tv_sec  - timer->time.tv_sec) * 1000000000;
    *nanoseconds += (current_time.tv_nsec - timer->time.tv_nsec);

    return 0;
}

int s2n_timer_reset(struct s2n_timer *timer, uint64_t *nanoseconds)
{
    struct timespec previous_time = timer->time;

    GUARD(s2n_timer_start(timer));

    *nanoseconds =  (timer->time.tv_sec  - previous_time.tv_sec) * 1000000000;
    *nanoseconds += (timer->time.tv_nsec - previous_time.tv_nsec);

    return 0;
}
#endif
