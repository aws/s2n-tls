/* posix-netdb/include/netdb.h - Strict C89 Implementation */
#ifndef POSIX_NETDB_STUB
#define POSIX_NETDB_STUB

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
/* clang-format off */
#include <winsock2.h>
#include <ws2tcpip.h>
#elif defined(__MSDOS__) || defined(__WATCOMC__)
/* DOS has no netdb.h by default */
#else
#if defined(__GNUC__) || defined(__clang__)
#pragma GCC system_header
#endif
#include_next <netdb.h>
/* clang-format on */

#ifdef __cplusplus
extern "C" {
#endif

#endif

#if defined(_WIN32)
/* gai_strerror is provided by ws2tcpip.h but sometimes as gai_strerrorA.
   Using the macro from there or redefining it. */
#endif

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* POSIX_NETDB_STUB */
