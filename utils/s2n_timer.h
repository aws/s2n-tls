#pragma once

#include <stdint.h>

#if defined(__APPLE__) && defined(__MACH__)
    
    struct s2n_timer {
        uint64_t time;
    };

#else

    #include <time.h>

    struct s2n_timer {
        struct timespec time;
    };

#endif

extern int s2n_timer_start(struct s2n_timer *timer);
extern int s2n_timer_reset(struct s2n_timer *timer, uint64_t *nanoseconds);
