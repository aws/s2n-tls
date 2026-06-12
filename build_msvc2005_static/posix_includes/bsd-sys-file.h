/* bsd-sys-file.h - Strict C89 Header */
#ifndef BSD_SYS_FILE_H
#define BSD_SYS_FILE_H

/**
 * @file bsd-sys-file.h
 * @brief POSIX sys/file.h implementation for MSVC
 *
 * This header provides the POSIX flock function
 * mapped to Windows file locking APIs.
 */

#if defined(_MSC_VER) || defined(_WIN32) || defined(__WATCOMC__) ||            \
    defined(__DOS__)

#define LOCK_SH 1
#define LOCK_EX 2
#define LOCK_NB 4
#define LOCK_UN 8

/**
 * @brief Apply or remove an advisory lock on the open file.
 *
 * @param fd The file descriptor to lock.
 * @param operation The operation to perform (LOCK_SH, LOCK_EX, LOCK_NB,
 * LOCK_UN).
 * @return 0 on success, -1 on error with errno set appropriately.
 */
int posix_flock(int fd, int operation);

#ifndef flock
#define flock posix_flock
#endif

#else /* Not MSVC/Windows */

/* clang-format off */
#include <sys/file.h>
/* clang-format on */

#ifdef __cplusplus
extern "C" {
#endif

#endif /* defined(_MSC_VER) || defined(_WIN32) || defined(__WATCOMC__) ||      \
          defined(__DOS__) */

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* BSD_SYS_FILE_H */
