#ifndef BSD_PTHREAD_NP_H
#define BSD_PTHREAD_NP_H

/* clang-format off */
#include <pthread.h>
#include <stddef.h>
/* clang-format on */

#ifdef __cplusplus
extern "C" {
#endif

#if defined(_WIN32)
/** \brief pthread_setaffinity_np function. */
int pthread_setaffinity_np(pthread_t thread, size_t cpusetsize,
                           const void *cpuset);
#endif

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
