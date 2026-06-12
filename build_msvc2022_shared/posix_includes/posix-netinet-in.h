/* posix-netinet-in.h - Strict C89 Header */
#ifndef POSIX_NETINET_IN_H
#define POSIX_NETINET_IN_H

#if defined(_MSC_VER) || defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
/* clang-format off */
#include <winsock2.h>
#include <ws2tcpip.h>
/* clang-format on */
#elif defined(__MSDOS__) || defined(__WATCOMC__)
/* clang-format off */
#if !defined(_MSC_VER) || _MSC_VER >= 1600
#include <stdint.h>
#endif
/* clang-format on */
#ifndef IPPROTO_IP
#define IPPROTO_IP 0
#endif
#ifndef IPPROTO_TCP
#define IPPROTO_TCP 6
#endif
#ifndef IPPROTO_UDP
#define IPPROTO_UDP 17
#endif
#else
/* clang-format off */
#include <netinet/in.h>
/* clang-format on */
#endif /* defined(_MSC_VER) || defined(_WIN32) */

#ifdef __cplusplus
extern "C" {
#endif

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* POSIX_NETINET_IN_H */
