/* posix-arpa-inet.h - Strict C89 Header */
#ifndef POSIX_ARPA_INET_H
#define POSIX_ARPA_INET_H

/**
 * @file posix-arpa-inet.h
 * @brief POSIX arpa/inet.h implementation for MSVC
 *
 * This header provides the POSIX inet_aton function
 * implemented using safe Microsoft CRT extensions.
 */

#if defined(_MSC_VER) || defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
/* clang-format off */
#include <winsock2.h>
#include <ws2tcpip.h>
#elif defined(__MSDOS__) || defined(__WATCOMC__)
#if !defined(_MSC_VER) || _MSC_VER >= 1600
#include <stdint.h>
#endif
struct in_addr {
    uint32_t s_addr;
};
#ifndef htonl
#define posix_htonl(x) ((((x) & 0xff000000) >> 24) | (((x) & 0x00ff0000) >> 8) | (((x) & 0x0000ff00) << 8) | (((x) & 0x000000ff) << 24))
#define htonl(x) posix_htonl(x)
#endif
#else
#include <arpa/inet.h>
#endif
/* clang-format on */

#ifdef __cplusplus
extern "C" {
#endif

#if defined(_MSC_VER) || defined(_WIN32) || defined(__MSDOS__) ||              \
    defined(__WATCOMC__)

/**
 * @brief Converts the Internet host address cp from the IPv4 numbers-and-dots
 * notation into binary form.
 *
 * @param cp The input IP address string.
 * @param inp Pointer to a struct in_addr where the result will be stored.
 * @return 1 if the address is valid, 0 if not.
 */
int posix_inet_aton(const char *cp, struct in_addr *inp);

#ifndef inet_aton
#define inet_aton posix_inet_aton
#endif

#endif /* defined(_MSC_VER) || defined(_WIN32) */

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* POSIX_ARPA_INET_H */
