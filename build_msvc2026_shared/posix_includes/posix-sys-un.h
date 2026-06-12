/* posix-sys-un.h - Strict C89 Header */
#ifndef POSIX_SYS_UN_H
#define POSIX_SYS_UN_H

#if defined(_MSC_VER) || defined(_WIN32)

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
/* clang-format off */
#include <afunix.h>
#include <winsock2.h>

#else

#include <sys/un.h>
/* clang-format on */

#ifdef __cplusplus
extern "C" {
#endif

#endif /* defined(_MSC_VER) || defined(_WIN32) */

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* POSIX_SYS_UN_H */
