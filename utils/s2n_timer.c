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

int s2n_timer_reset(struct s2n_timer *timer, uint64_t *nanoseconds)
{
    mach_timebase_info_data_t conversion_factor;
    uint64_t previous_time = timer->time;

    GUARD(s2n_timer_start(timer));

    *nanoseconds = timer->time - previous_time;

    mach_timebase_info(&conversion_factor);   
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
    GUARD(timer_gettime(S2N_CLOCK, &timer->last_time));

    return 0;
}

int s2n_timer_reset(struct s2n_timer *timer, uint64_t *nanoseconds) 
{
    struct timespec previous_time = timer->time;

    GUARD(s2n_timer_start(timer));

    *nanoseconds = (previous_time.tv_sec - timer->time.tv_sec) * 1000000000;
    *nanoseconds += (previous_time.tv_nsec - timer->time.tv_nsec);

    return 0;
}
#endif
