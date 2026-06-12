/* posix-sys-ioctl.h - Strict C89 Header */
#ifndef POSIX_SYS_IOCTL_H
#define POSIX_SYS_IOCTL_H

/**
 * @file posix-sys-ioctl.h
 * @brief POSIX sys/ioctl.h implementation for MSVC
 *
 * This header provides the POSIX ioctl function
 * mapping to Winsock's ioctlsocket API.
 */

#if defined(_MSC_VER) || defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
/* clang-format off */
#include <winsock2.h>
#elif defined(__MSDOS__) || defined(__WATCOMC__)
/* DOS has no sys/ioctl.h */
#else
#include <sys/ioctl.h>
#endif
/* clang-format on */

#ifdef __cplusplus
extern "C" {
#endif

#if defined(_MSC_VER) || defined(_WIN32) || defined(__MSDOS__) ||              \
    defined(__WATCOMC__)

#ifndef TIOCGWINSZ
#define TIOCGWINSZ 0x5413
#endif

#ifndef TIOCSWINSZ
#define TIOCSWINSZ 0x5414
#endif

#ifndef FIONREAD
#define FIONREAD 0x4004667f
#endif

#ifndef FIONBIO
#define FIONBIO 0x8004667e
#endif

struct winsize {
  unsigned short ws_row;
  unsigned short ws_col;
  unsigned short ws_xpixel;
  unsigned short ws_ypixel;
};

/**
 * @brief Performs device-specific control functions on a socket.
 *
 * @param fd The file descriptor/socket on which to perform the operation.
 * @param request The operation code to perform.
 * @param ... Additional arguments.
 * @return 0 on success, -1 on error with errno set appropriately.
 */
/* clang-format off */
#if !defined(_MSC_VER) || _MSC_VER >= 1600
#include <stdint.h>
#endif
/* clang-format on */
int posix_ioctl(intptr_t fd, unsigned long request, ...);

#define ioctl posix_ioctl
#define ioctlsocket posix_ioctl

#endif /* defined(_MSC_VER) || defined(_WIN32) */

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* POSIX_SYS_IOCTL_H */
