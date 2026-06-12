/* posix-sys-resource.h - Strict C89 Header */
#ifndef POSIX_SYS_RESOURCE_H
#define POSIX_SYS_RESOURCE_H

/**
 * @file posix-sys-resource.h
 * @brief POSIX sys/resource.h implementation for MSVC
 *
 * This header maps getrusage, getrlimit, and setrlimit functions
 * using Windows process APIs.
 */

/* clang-format off */
#if defined(_MSC_VER) || defined(_WIN32)
#ifndef _TIMEVAL_DEFINED
#include <winsock2.h>
#endif
#elif defined(__MSDOS__) || defined(__WATCOMC__)
#ifndef _TIMEVAL_DEFINED
struct timeval {
  long tv_sec;
  long tv_usec;
};
#define _TIMEVAL_DEFINED
#endif
/* DOS has no sys/resource.h */
#else /* Not MSVC/Windows */
#include <sys/resource.h>
#endif /* defined(_MSC_VER) || defined(_WIN32) */
/* clang-format on */

#ifdef __cplusplus
extern "C" {
#endif

#if defined(_MSC_VER) || defined(_WIN32) || defined(__MSDOS__) ||              \
    defined(__WATCOMC__)

#define RUSAGE_SELF 0
#define RUSAGE_CHILDREN -1

/**
 * @brief Structure containing resource usage metrics.
 */
struct rusage {
  struct timeval ru_utime; /* user CPU time used */
  struct timeval ru_stime; /* system CPU time used */
  long ru_maxrss;          /* maximum resident set size */
  long ru_ixrss;           /* integral shared memory size */
  long ru_idrss;           /* integral unshared data size */
  long ru_isrss;           /* integral unshared stack size */
  long ru_minflt;          /* page reclaims (soft page faults) */
  long ru_majflt;          /* page faults (hard page faults) */
  long ru_nswap;           /* swaps */
  long ru_inblock;         /* block input operations */
  long ru_oublock;         /* block output operations */
  long ru_msgsnd;          /* IPC messages sent */
  long ru_msgrcv;          /* IPC messages received */
  long ru_nsignals;        /* signals received */
  long ru_nvcsw;           /* voluntary context switches */
  long ru_nivcsw;          /* involuntary context switches */
};

#define RLIMIT_CPU 0
#define RLIMIT_FSIZE 1
#define RLIMIT_DATA 2
#define RLIMIT_STACK 3
#define RLIMIT_CORE 4
#define RLIMIT_RSS 5
#define RLIMIT_NOFILE 7
#define RLIMIT_AS 9

typedef unsigned long rlim_t;

/**
 * @brief Structure indicating soft and hard limits.
 */
struct rlimit {
  rlim_t rlim_cur;
  rlim_t rlim_max;
};

/** \brief RLIM_INFINITY macro. */
#define RLIM_INFINITY (~0UL)

/**
 * @brief Retrieves system resource usage measures for the calling process.
 *
 * @param who Specifies whose resources should be measured (RUSAGE_SELF).
 * @param usage A pointer to the rusage struct to populate.
 * @return 0 on success, -1 on error.
 */
int posix_getrusage(int who, struct rusage *usage);

/**
 * @brief Gets resource limits.
 *
 * @param resource The resource to check limits for.
 * @param rlp The rlimit struct to populate.
 * @return 0 on success, -1 on error.
 */
int posix_getrlimit(int resource, struct rlimit *rlp);

/**
 * @brief Sets resource limits.
 *
 * @param resource The resource to set limits for.
 * @param rlp The new limits to apply.
 * @return 0 on success, -1 on error.
 */
int posix_setrlimit(int resource, const struct rlimit *rlp);

#ifndef getrusage
#define getrusage posix_getrusage
#endif
#ifndef getrlimit
#define getrlimit posix_getrlimit
#endif
#ifndef setrlimit
#define setrlimit posix_setrlimit
#endif

#endif /* defined(_MSC_VER) || defined(_WIN32) */

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* POSIX_SYS_RESOURCE_H */
