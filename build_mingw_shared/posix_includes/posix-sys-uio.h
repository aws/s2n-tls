/* posix-sys-uio.h - Strict C89 Header */
#ifndef POSIX_SYS_UIO_H
#define POSIX_SYS_UIO_H

/**
 * @file posix-sys-uio.h
 * @brief POSIX sys/uio.h implementation for MSVC
 *
 * This header provides the POSIX readv and writev functions
 * mapped to WSASend and _write system calls.
 */

/* clang-format off */
#if defined(_MSC_VER) || defined(_WIN32)
#include <stddef.h> /* size_t */
#elif defined(__MSDOS__) || defined(__WATCOMC__)
#include <stddef.h> /* size_t */
#else
#include <sys/uio.h>
#endif
/* clang-format on */

#ifdef __cplusplus
extern "C" {
#endif

#if defined(_MSC_VER) || defined(_WIN32) || defined(__MSDOS__) ||              \
    defined(__WATCOMC__)

/**
 * @brief Vector structure for scatter/gather I/O operations.
 */
#ifndef AUTO_WIN_MSVC_SKIP_IOVEC
struct iovec {
  void *iov_base; /* Base address */
  size_t iov_len; /* Length */
};
#endif

/**
 * @brief Reads data into multiple buffers.
 *
 * @param fd The file descriptor/socket to read from.
 * @param iov A pointer to an array of iovec structures.
 * @param iovcnt The number of elements in the iov array.
 * @return On success, the total bytes read. On error, -1 with errno set
 * appropriately.
 */
long posix_readv(int fd, const struct iovec *iov, int iovcnt);

/**
 * @brief Writes data from multiple buffers.
 *
 * @param fd The file descriptor/socket to write to.
 * @param iov A pointer to an array of iovec structures.
 * @param iovcnt The number of elements in the iov array.
 * @return On success, the total bytes written. On error, -1 with errno set
 * appropriately.
 */
long posix_writev(int fd, const struct iovec *iov, int iovcnt);

#ifndef readv
#define readv posix_readv
#endif
#ifndef writev
#define writev posix_writev
#endif

#endif /* defined(_MSC_VER) || defined(_WIN32) */

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* POSIX_SYS_UIO_H */
