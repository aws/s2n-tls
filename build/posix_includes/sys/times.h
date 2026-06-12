/* posix-times.h - Strict C89 Implementation */
#ifndef POSIX_TIMES_H
#define POSIX_TIMES_H

/* clang-format off */
#include <time.h>
/* clang-format on */

#ifdef __cplusplus
extern "C" {
#endif

#if defined(_MSC_VER) && !defined(__clang__)
#define POSIX_TIMES_MSVC 1
#endif

#if defined(POSIX_TIMES_MSVC)

/* We need clock_t which is in <time.h> */

struct tms {
  clock_t tms_utime;  /* user time */
  clock_t tms_stime;  /* system time */
  clock_t tms_cutime; /* user time of children */
  clock_t tms_cstime; /* system time of children */
};

clock_t posix_times(struct tms *buf);

#ifndef times
#define times posix_times
#endif

#endif /* POSIX_TIMES_MSVC */

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* POSIX_TIMES_H */
