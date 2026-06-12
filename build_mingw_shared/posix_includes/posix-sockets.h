/* posix-sockets.h - Strict C89 Header */
#ifndef POSIX_SOCKETS_H
#define POSIX_SOCKETS_H

#ifndef NAMESPACE_WIN_SHIM_H
#define NAMESPACE_WIN_SHIM_H
#endif
#include <posix-poll.h>
#include <posix-sys-ioctl.h>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
/* clang-format off */
#include <winsock2.h>
#include <ws2tcpip.h>
#include <errno.h>

#ifndef EWOULDBLOCK
#define EWOULDBLOCK WSAEWOULDBLOCK
#endif
#ifndef EINPROGRESS
#define EINPROGRESS WSAEINPROGRESS
#endif
#ifndef EALREADY
#define EALREADY WSAEALREADY
#endif
#ifndef ENOTSOCK
#define ENOTSOCK WSAENOTSOCK
#endif
#ifndef EDESTADDRREQ
#define EDESTADDRREQ WSAEDESTADDRREQ
#endif
#ifndef EMSGSIZE
#define EMSGSIZE WSAEMSGSIZE
#endif
#ifndef EPROTOTYPE
#define EPROTOTYPE WSAEPROTOTYPE
#endif
#ifndef ENOPROTOOPT
#define ENOPROTOOPT WSAENOPROTOOPT
#endif
#ifndef EPROTONOSUPPORT
#define EPROTONOSUPPORT WSAEPROTONOSUPPORT
#endif
#ifndef EOPNOTSUPP
#define EOPNOTSUPP WSAEOPNOTSUPP
#endif
#ifndef EAFNOSUPPORT
#define EAFNOSUPPORT WSAEAFNOSUPPORT
#endif
#ifndef EADDRINUSE
#define EADDRINUSE WSAEADDRINUSE
#endif
#ifndef EADDRNOTAVAIL
#define EADDRNOTAVAIL WSAEADDRNOTAVAIL
#endif
#ifndef ENETDOWN
#define ENETDOWN WSAENETDOWN
#endif
#ifndef ENETUNREACH
#define ENETUNREACH WSAENETUNREACH
#endif
#ifndef ENETRESET
#define ENETRESET WSAENETRESET
#endif
#ifndef ECONNABORTED
#define ECONNABORTED WSAECONNABORTED
#endif
#ifndef ECONNRESET
#define ECONNRESET WSAECONNRESET
#endif
#ifndef ENOBUFS
#define ENOBUFS WSAENOBUFS
#endif
#ifndef EISCONN
#define EISCONN WSAEISCONN
#endif
#ifndef ENOTCONN
#define ENOTCONN WSAENOTCONN
#endif
#ifndef ETIMEDOUT
#define ETIMEDOUT WSAETIMEDOUT
#endif
#ifndef ECONNREFUSED
#define ECONNREFUSED WSAECONNREFUSED
#endif
#ifndef ELOOP
#define ELOOP WSAELOOP
#endif
#ifndef ENAMETOOLONG
#define ENAMETOOLONG WSAENAMETOOLONG
#endif
#ifndef EHOSTUNREACH
#define EHOSTUNREACH WSAEHOSTUNREACH
#endif
#ifndef ENOTEMPTY
#define ENOTEMPTY WSAENOTEMPTY
#endif

#else
#include <sys/socket.h>
#include <sys/select.h>
#include <netdb.h>
#include <poll.h>
#include <stddef.h>
#include <errno.h>
#endif

/* POSIX types that need to be defined safely for our stubs */

#if defined(_WIN32) && defined(_MSC_VER) && _MSC_VER < 1600
typedef unsigned __int32 uint32_t;
#else
#if !defined(_MSC_VER) || _MSC_VER >= 1600
#include <stdint.h>
#endif
#endif

#ifndef _POSIX_SSIZE_T_DEFINED
#ifdef _WIN64
typedef __int64 posix_ssize_t;
#else
typedef int posix_ssize_t;
#endif
#define _POSIX_SSIZE_T_DEFINED
#endif

typedef int posix_socklen_t;
typedef unsigned int posix_nfds_t;

#ifdef _WIN32
#include <posix-sys-uio.h>

struct msghdr {
  void *msg_name;
  posix_socklen_t msg_namelen;
  struct iovec *msg_iov;
  int msg_iovlen;
  void *msg_control;
  posix_socklen_t msg_controllen;
  int msg_flags;
};
#endif /* _WIN32 */

#ifdef _WIN32
#ifndef _TIMESPEC_DEFINED
#define _TIMESPEC_DEFINED
#if defined(_MSC_VER) && _MSC_VER >= 1900
#include <time.h>
/* clang-format on */

#ifdef __cplusplus
extern "C" {
#endif

#else
struct timespec {
  long tv_sec;
  long tv_nsec;
};
#endif
#endif
#endif /* _WIN32 */

/* Opaque structures for the stubs so they compile cross platform */
struct addrinfo;
struct hostent;
struct sockaddr;
struct netent;
struct protoent;
struct servent;

#ifdef _WIN32
#ifndef POLLIN
struct pollfd {
  SOCKET fd;
  short events;
  short revents;
};
#define POLLRDNORM 0x0100
#define POLLRDBAND 0x0200
#define POLLIN (POLLRDNORM | POLLRDBAND)
#define POLLPRI 0x0400

#define POLLWRNORM 0x0010
#define POLLOUT (POLLWRNORM)
#define POLLWRBAND 0x0020

#define POLLERR 0x0001
#define POLLHUP 0x0002
#define POLLNVAL 0x0004
#endif
#endif
struct pollfd;

typedef struct fd_set fd_set;
struct timeval;
struct msghdr;
struct iovec;
struct timespec;

/**
 * @brief POSIX endhostent stub
 * @return mapped value or -1 with errno EINVAL
 */
void posix_endhostent(void);
/**
 * @brief POSIX endnetent stub
 * @return mapped value or -1 with errno EINVAL
 */
void posix_endnetent(void);
/**
 * @brief POSIX endprotoent stub
 * @return mapped value or -1 with errno EINVAL
 */
void posix_endprotoent(void);
/**
 * @brief POSIX endservent stub
 * @return mapped value or -1 with errno EINVAL
 */
void posix_endservent(void);
/**
 * @brief POSIX freeaddrinfo stub
 * @return mapped value or -1 with errno EINVAL
 */
void posix_freeaddrinfo(struct addrinfo *ai);
/**
 * @brief POSIX gai_strerror stub
 * @return mapped value or -1 with errno EINVAL
 */
const char *posix_gai_strerror(int ecode);
/**
 * @brief POSIX getaddrinfo stub
 * @return mapped value or -1 with errno EINVAL
 */
int posix_getaddrinfo(const char *nodename, const char *servname,
                      const struct addrinfo *hints, struct addrinfo **res);
/**
 * @brief POSIX gethostbyaddr stub
 * @return mapped value or -1 with errno EINVAL
 */
struct hostent *posix_gethostbyaddr(const void *addr, posix_socklen_t len,
                                    int type);
/**
 * @brief POSIX gethostbyname stub
 * @return mapped value or -1 with errno EINVAL
 */
struct hostent *posix_gethostbyname(const char *name);
/**
 * @brief POSIX gethostent stub
 * @return mapped value or -1 with errno EINVAL
 */
struct hostent *posix_gethostent(void);
/**
 * @brief POSIX getnameinfo stub
 * @return mapped value or -1 with errno EINVAL
 */
int posix_getnameinfo(const struct sockaddr *sa, posix_socklen_t salen,
                      char *node, posix_socklen_t nodelen, char *service,
                      posix_socklen_t servicelen, int flags);
/**
 * @brief POSIX getnetbyaddr stub
 * @return mapped value or -1 with errno EINVAL
 */
struct netent *posix_getnetbyaddr(uint32_t net, int type);
/**
 * @brief POSIX getnetbyname stub
 * @return mapped value or -1 with errno EINVAL
 */
struct netent *posix_getnetbyname(const char *name);
/**
 * @brief POSIX getnetent stub
 * @return mapped value or -1 with errno EINVAL
 */
struct netent *posix_getnetent(void);
/**
 * @brief POSIX getprotobyname stub
 * @return mapped value or -1 with errno EINVAL
 */
struct protoent *posix_getprotobyname(const char *name);
/**
 * @brief POSIX getprotobynumber stub
 * @return mapped value or -1 with errno EINVAL
 */
struct protoent *posix_getprotobynumber(int proto);
/**
 * @brief POSIX getprotoent stub
 * @return mapped value or -1 with errno EINVAL
 */
struct protoent *posix_getprotoent(void);
/**
 * @brief POSIX getservbyname stub
 * @return mapped value or -1 with errno EINVAL
 */
struct servent *posix_getservbyname(const char *name, const char *proto);
/**
 * @brief POSIX getservbyport stub
 * @return mapped value or -1 with errno EINVAL
 */
struct servent *posix_getservbyport(int port, const char *proto);
/**
 * @brief POSIX getservent stub
 * @return mapped value or -1 with errno EINVAL
 */
struct servent *posix_getservent(void);
/**
 * @brief POSIX sethostent stub
 * @return mapped value or -1 with errno EINVAL
 */
void posix_sethostent(int stayopen);
/**
 * @brief POSIX setnetent stub
 * @return mapped value or -1 with errno EINVAL
 */
void posix_setnetent(int stayopen);
/**
 * @brief POSIX setprotoent stub
 * @return mapped value or -1 with errno EINVAL
 */
void posix_setprotoent(int stayopen);
/**
 * @brief POSIX setservent stub
 * @return mapped value or -1 with errno EINVAL
 */
void posix_setservent(int stayopen);
/**
 * @brief POSIX poll implementation
 * @param fds Array of pollfd structures
 * @param nfds Number of file descriptors in the array
 * @param timeout Timeout in milliseconds
 * @return Number of ready file descriptors, or -1 on error
 */
int posix_poll(struct pollfd *fds, unsigned long nfds, int timeout);
/**
 * @brief POSIX pselect implementation
 * @param nfds Highest file descriptor plus one (ignored on Windows)
 * @param readfds fd_set for read events
 * @param writefds fd_set for write events
 * @param errorfds fd_set for error events
 * @param timeout Timeout as a timespec structure
 * @param sigmask Signal mask (ignored on Windows)
 * @return Number of ready file descriptors, or -1 on error
 */
int posix_pselect(int nfds, fd_set *readfds, fd_set *writefds, fd_set *errorfds,
                  const struct timespec *timeout, const void *sigmask);
/**
 * @brief POSIX select stub
 * @return mapped value or -1 with errno EINVAL
 */
int posix_select(int nfds, fd_set *readfds, fd_set *writefds, fd_set *errorfds,
                 struct timeval *timeout);
/**
 * @brief POSIX accept stub
 * @return mapped value or -1 with errno EINVAL
 */
int posix_accept(intptr_t socket, struct sockaddr *address,
                 posix_socklen_t *address_len);
/**
 * @brief POSIX bind stub
 * @return mapped value or -1 with errno EINVAL
 */
int posix_bind(intptr_t socket, const struct sockaddr *address,
               posix_socklen_t address_len);
/**
 * @brief POSIX connect stub
 * @return mapped value or -1 with errno EINVAL
 */
int posix_connect(intptr_t socket, const struct sockaddr *address,
                  posix_socklen_t address_len);
/**
 * @brief POSIX getpeername stub
 * @return mapped value or -1 with errno EINVAL
 */
int posix_getpeername(intptr_t socket, struct sockaddr *address,
                      posix_socklen_t *address_len);
/**
 * @brief POSIX getsockname stub
 * @return mapped value or -1 with errno EINVAL
 */
int posix_getsockname(intptr_t socket, struct sockaddr *address,
                      posix_socklen_t *address_len);
/**
 * @brief POSIX getsockopt stub
 * @return mapped value or -1 with errno EINVAL
 */
int posix_getsockopt(intptr_t socket, int level, int option_name,
                     void *option_value, posix_socklen_t *option_len);
/**
 * @brief POSIX listen stub
 * @return mapped value or -1 with errno EINVAL
 */
int posix_listen(intptr_t socket, int backlog);
/**
 * @brief POSIX recv stub
 * @return mapped value or -1 with errno EINVAL
 */
posix_ssize_t posix_recv(intptr_t socket, void *buffer, size_t length,
                         int flags);
/**
 * @brief POSIX recvfrom stub
 * @return mapped value or -1 with errno EINVAL
 */
posix_ssize_t posix_recvfrom(intptr_t socket, void *buffer, size_t length,
                             int flags, struct sockaddr *address,
                             posix_socklen_t *address_len);
/**
 * @brief POSIX recvmsg stub
 * @return mapped value or -1 with errno EINVAL
 */
posix_ssize_t posix_recvmsg(intptr_t socket, struct msghdr *message, int flags);
/**
 * @brief POSIX send stub
 * @return mapped value or -1 with errno EINVAL
 */
posix_ssize_t posix_send(intptr_t socket, const void *message, size_t length,
                         int flags);
/**
 * @brief POSIX sendmsg stub
 * @return mapped value or -1 with errno EINVAL
 */
posix_ssize_t posix_sendmsg(intptr_t socket, const struct msghdr *message,
                            int flags);
/**
 * @brief POSIX sendto stub
 * @return mapped value or -1 with errno EINVAL
 */
posix_ssize_t posix_sendto(intptr_t socket, const void *message, size_t length,
                           int flags, const struct sockaddr *dest_addr,
                           posix_socklen_t dest_len);
/**
 * @brief POSIX setsockopt stub
 * @return mapped value or -1 with errno EINVAL
 */
int posix_setsockopt(intptr_t socket, int level, int option_name,
                     const void *option_value, posix_socklen_t option_len);
/**
 * @brief POSIX shutdown stub
 * @return mapped value or -1 with errno EINVAL
 */
int posix_shutdown(intptr_t socket, int how);
/**
 * @brief POSIX socket stub
 * @return mapped value or -1 with errno EINVAL
 */
int posix_socket(int domain, int type, int protocol);
/**
 * @brief POSIX socketpair stub
 * @return mapped value or -1 with errno EINVAL
 */
int posix_socketpair(int domain, int type, int protocol,
                     intptr_t socket_vector[2]);

#ifdef _WIN32
/* Map POSIX names to our posix_ prefixes */
#define endhostent posix_endhostent
#define endnetent posix_endnetent
#define endprotoent posix_endprotoent
#define endservent posix_endservent
#ifdef freeaddrinfo
#undef freeaddrinfo
#endif
#define freeaddrinfo posix_freeaddrinfo
#ifdef gai_strerror
#undef gai_strerror
#endif
#define gai_strerror posix_gai_strerror
#ifdef getaddrinfo
#undef getaddrinfo
#endif
#define getaddrinfo posix_getaddrinfo
#define gethostbyaddr posix_gethostbyaddr
#define gethostbyname posix_gethostbyname
#define gethostent posix_gethostent
#ifdef getnameinfo
#undef getnameinfo
#endif
#define getnameinfo posix_getnameinfo
#define getnetbyaddr posix_getnetbyaddr
#define getnetbyname posix_getnetbyname
#define getnetent posix_getnetent
#define getprotobyname posix_getprotobyname
#define getprotobynumber posix_getprotobynumber
#define getprotoent posix_getprotoent
#define getservbyname posix_getservbyname
#define getservbyport posix_getservbyport
#define getservent posix_getservent
#define sethostent posix_sethostent
#define setnetent posix_setnetent
#define setprotoent posix_setprotoent
#define setservent posix_setservent
#define poll posix_poll
#define pselect posix_pselect
#define select posix_select
#define accept posix_accept
#define bind posix_bind
#define connect posix_connect
#define getpeername posix_getpeername
#define getsockname posix_getsockname
#define getsockopt posix_getsockopt
#define listen posix_listen
#define recv posix_recv
#define recvfrom posix_recvfrom
#define recvmsg posix_recvmsg
#define send posix_send
#define sendmsg posix_sendmsg
#define sendto posix_sendto
#define setsockopt posix_setsockopt
#define shutdown posix_shutdown
#define socket posix_socket
#define socketpair posix_socketpair

#endif /* _WIN32 */

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* POSIX_SOCKETS_H */
