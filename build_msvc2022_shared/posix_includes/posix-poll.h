#ifndef POSIX_POLL_H
#define POSIX_POLL_H

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
/* clang-format off */
#include <winsock2.h>
/* clang-format on */

#ifdef __cplusplus
extern "C" {
#endif

/* Fallback if struct pollfd isn't defined by older winsock2.h */
#if !defined(_WIN32_WINNT) || (_WIN32_WINNT < 0x0600)
struct pollfd {
  SOCKET fd;
  short events;
  short revents;
};
#endif

#ifndef POLLIN
#define POLLIN 0x01
#define POLLPRI 0x02
#define POLLOUT 0x04
#define POLLERR 0x08
#define POLLHUP 0x10
#define POLLNVAL 0x20
#endif

int posix_poll(struct pollfd *fds, unsigned long nfds, int timeout);

#undef poll
#define poll posix_poll
#define WSAPoll posix_poll

#ifdef __cplusplus
}
#endif /* __cplusplus */
#endif /* _WIN32 */

#endif /* POSIX_POLL_H */
