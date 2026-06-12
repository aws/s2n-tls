#ifndef LINUX_EPOLL_H
#define LINUX_EPOLL_H

#if defined(_WIN32) && !defined(__CYGWIN__) &&                                 \
    (!defined(_MSC_VER) || _MSC_VER >= 1600)
/* clang-format off */
#if !defined(_MSC_VER) || _MSC_VER >= 1600
#include <stdint.h>
#endif
#include <wepoll.h>
#elif defined(__linux__)
#include <sys/epoll.h>
#endif
/* clang-format on */

#ifdef __cplusplus
extern "C" {
#endif

#if defined(_WIN32) && !defined(__CYGWIN__) &&                                 \
    (!defined(_MSC_VER) || _MSC_VER >= 1600)
/** \brief posix_epoll_create function. */
int posix_epoll_create(int size);
/** \brief posix_epoll_create1 function. */
int posix_epoll_create1(int flags);
/** \brief posix_epoll_ctl function. */
int posix_epoll_ctl(int epfd, int op, int fd, struct epoll_event *event);
/** \brief posix_epoll_wait function. */
int posix_epoll_wait(int epfd, struct epoll_event *events, int maxevents,
                     int timeout);
/** \brief posix_epoll_close function. */
int posix_epoll_close(int epfd);
#define epoll_create posix_epoll_create
#define epoll_create1 posix_epoll_create1
#define epoll_ctl posix_epoll_ctl
#define epoll_wait posix_epoll_wait
#elif defined(_WIN32) && !defined(__CYGWIN__)
/** \brief posix_epoll_create function. */
int posix_epoll_create(int size);
/** \brief posix_epoll_create1 function. */
int posix_epoll_create1(int flags);
/** \brief posix_epoll_ctl function. */
int posix_epoll_ctl(int epfd, int op, int fd, void *event);
/** \brief posix_epoll_wait function. */
int posix_epoll_wait(int epfd, void *events, int maxevents, int timeout);
/** \brief posix_epoll_close function. */
int posix_epoll_close(int epfd);
#define epoll_create posix_epoll_create
#define epoll_create1 posix_epoll_create1
#define epoll_ctl posix_epoll_ctl
#define epoll_wait posix_epoll_wait
#elif defined(__linux__)
/* Includes moved to the top */
#else
/** \brief posix_epoll_create function. */
int posix_epoll_create(int size);
/** \brief posix_epoll_create1 function. */
int posix_epoll_create1(int flags);
/** \brief posix_epoll_ctl function. */
int posix_epoll_ctl(int epfd, int op, int fd, void *event);
/** \brief posix_epoll_wait function. */
int posix_epoll_wait(int epfd, void *events, int maxevents, int timeout);
/** \brief posix_epoll_close function. */
int posix_epoll_close(int epfd);
#define epoll_create posix_epoll_create
#define epoll_create1 posix_epoll_create1
#define epoll_ctl posix_epoll_ctl
#define epoll_wait posix_epoll_wait
#endif

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* LINUX_EPOLL_H */
