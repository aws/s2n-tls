/* posix-time.h - Strict C89 Header */
#ifndef POSIX_TIME_H
#define POSIX_TIME_H

/* clang-format off */
#include <time.h>

#if defined(_WIN32) || defined(__MSDOS__) || defined(__WATCOMC__)

#if defined(_WIN32)
#include <sys/utime.h>
#include <winsock2.h>
#endif

#if defined(_MSC_VER) && _MSC_VER >= 1900
/* UCRT defines struct timespec in time.h */
#else
#ifndef _TIMESPEC_DEFINED
#define _TIMESPEC_DEFINED
/**
 * @brief Structure for representing time with nanosecond precision.
 */
struct timespec {
  time_t tv_sec; /**< Seconds. */
  long tv_nsec;  /**< Nanoseconds. */
};
#endif
#endif

#ifndef _WINSOCK2API_
#ifndef _TIMEVAL_DEFINED
#define _TIMEVAL_DEFINED
/**
 * @brief Structure for representing time with microsecond precision.
 */
struct timeval {
  long tv_sec;  /**< Seconds. */
  long tv_usec; /**< Microseconds. */
};
#endif
#endif

#ifndef _TIMEZONE_DEFINED
#define _TIMEZONE_DEFINED
/**
 * @brief Structure for representing timezone information (obsolete).
 */
struct timezone {
  int tz_minuteswest; /**< Minutes west of Greenwich. */
  int tz_dsttime;     /**< Type of DST correction. */
};
#endif

#ifndef _ITIMERVAL_DEFINED
#define _ITIMERVAL_DEFINED
/**
 * @brief Structure for configuring an interval timer.
 */
struct itimerval {
  struct timeval it_interval; /**< Timer interval. */
  struct timeval it_value;    /**< Current value. */
};
#endif

/* Interval timer definitions */
#define ITIMER_REAL                                                            \
  0 /**< Decrements in real time, and delivers SIGALRM upon expiration. */
#define ITIMER_VIRTUAL                                                         \
  1 /**< Decrements only when the process is executing, and delivers SIGVTALRM \
       upon expiration. */
#define ITIMER_PROF                                                            \
  2 /**< Decrements both when the process executes and when the system is      \
       executing on behalf of the process. */

/* Clock Types */
#ifndef CLOCK_REALTIME
#define CLOCK_REALTIME 0
#endif
#ifndef CLOCK_MONOTONIC
#define CLOCK_MONOTONIC 1
#endif
#ifndef CLOCK_PROCESS_CPUTIME_ID
#define CLOCK_PROCESS_CPUTIME_ID 2
#endif
#ifndef CLOCK_THREAD_CPUTIME_ID
#define CLOCK_THREAD_CPUTIME_ID 3
#endif

#define utime _utime     /**< Map utime to _utime on Windows */
#define tzset _tzset     /**< Map tzset to _tzset on Windows */
#define utimbuf _utimbuf /**< Map utimbuf to _utimbuf on Windows */

/* Functions that require polyfill on Windows */

/**
 * @brief Format string for 64-bit integers, accommodating different compilers.
 */


/**
 * @brief Gets the value of an interval timer.
 * @param which The timer to get (e.g., ITIMER_REAL).
 * @param value A pointer to an itimerval structure to store the value.
 * @return 0 on success, -1 on error.
 */
int getitimer(int which, struct itimerval *value);

/**
 * @brief Gets the current time of day.
 * @param tv A pointer to a timeval structure to store the time.
 * @param tz A pointer to a timezone structure to store the timezone (obsolete,
 * usually NULL).
 * @return 0 on success, -1 on error.
 */
int gettimeofday(struct timeval *tv, struct timezone *tz);

/**
 * @brief Sets the value of an interval timer.
 * @param which The timer to set (e.g., ITIMER_REAL).
 * @param value A pointer to an itimerval structure containing the new value.
 * @param ovalue A pointer to an itimerval structure to store the old value
 * (optional).
 * @return 0 on success, -1 on error.
 */
int setitimer(int which, const struct itimerval *value,
              struct itimerval *ovalue);

/**
 * @brief Sets the access and modification times of a file with microsecond
 * precision.
 * @param filename The name of the file.
 * @param times An array of two timeval structures (access time, modification
 * time). If NULL, times are set to current time.
 * @return 0 on success, -1 on error.
 */
int utimes(const char *filename, const struct timeval times[2]);

/**
 * @brief Get the current time of the specified clock.
 * @param clk_id The clock ID (e.g., CLOCK_REALTIME, CLOCK_MONOTONIC).
 * @param tp A pointer to a timespec structure to store the time.
 * @return 0 on success, -1 on error.
 */
int clock_gettime(int clk_id, struct timespec *tp);

/**
 * @brief High-resolution sleep with nanosecond precision.
 * @param req The requested time to sleep.
 * @param rem The remaining time if interrupted (optional).
 * @return 0 on success, -1 on error.
 */
int nanosleep(const struct timespec *req, struct timespec *rem);

/**
 * @brief Thread-safe version of localtime.
 * @param timep A pointer to the time_t value to convert.
 * @param result A pointer to a tm structure to store the result.
 * @return A pointer to the result, or NULL on error.
 */
struct tm *localtime_r(const time_t *timep, struct tm *result);

#else /* _WIN32 */

#include <sys/time.h>
#include <utime.h>
/* clang-format on */

#ifdef __cplusplus
extern "C" {
#endif

#endif /* _WIN32 */

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* POSIX_TIME_H */
