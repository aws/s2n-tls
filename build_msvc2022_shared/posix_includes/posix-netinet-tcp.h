/* posix-netinet-tcp.h - Strict C89 Header */
#ifndef POSIX_NETINET_TCP_H
#define POSIX_NETINET_TCP_H

#if defined(_MSC_VER) || defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
/* clang-format off */
#include <winsock2.h>
#include <ws2tcpip.h>
#elif defined(__MSDOS__) || defined(__WATCOMC__)
#ifndef TCP_NODELAY
#define TCP_NODELAY 1
#endif
#else
#include <netinet/tcp.h>
/* clang-format on */

#ifdef __cplusplus
extern "C" {
#endif

#endif /* defined(_MSC_VER) || defined(_WIN32) */

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* POSIX_NETINET_TCP_H */
