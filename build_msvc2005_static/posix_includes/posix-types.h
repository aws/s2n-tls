/* posix-types.h - Strict C89 Header */
#ifndef POSIX_TYPES_H
#define POSIX_TYPES_H

#if defined(_WIN32) && !defined(__CYGWIN__)

/* clang-format off */
#include <basetsd.h>
#include <sys/types.h>
#include <time.h>

#if defined(__MINGW32__)
#include <winsock2.h>
#include <ws2tcpip.h>
/* MinGW natively provides these types, so we prevent redefining them. */
#define _PID_T_DEFINED
#define _SSIZE_T_DEFINED
#define _MODE_T_DEFINED
#define _OFF_T_DEFINED
#define _OFF64_T_DEFINED
#define _USECONDS_T_DEFINED
#define _DEV_T_DEFINED
#define _INO_T_DEFINED
#define _SOCKLEN_T_DEFINED
#define _CLOCK_T_DEFINED
#define _TIME_T_DEFINED
#define _CLOCKID_T_DEFINED
#endif

#if defined(__GNUC__)
#define POSIX_TYPES_EXTENSION __extension__
#else
#define POSIX_TYPES_EXTENSION
#endif

/**
 * @brief Process ID type.
 * MSVC defines this as int.
 */
#ifndef _PID_T_DEFINED
#define _PID_T_DEFINED
typedef int pid_t;
#endif

/**
 * @brief Signed size type.
 * MSVC defines this as SSIZE_T from basetsd.h.
 */
#ifndef _SSIZE_T_DEFINED
#define _SSIZE_T_DEFINED
typedef SSIZE_T ssize_t;
#endif

/**
 * @brief File mode type.
 * MSVC defines this as unsigned short.
 */
#ifndef _MODE_T_DEFINED
#define _MODE_T_DEFINED
typedef unsigned short mode_t;
#endif

#ifndef HAVE_MODE_T
#define HAVE_MODE_T 1
#endif
#ifndef HAVE_PID_T
#define HAVE_PID_T 1
#endif
#ifndef HAVE_ID_T
#define HAVE_ID_T 1
#endif
#ifndef HAVE_OFF_T
#define HAVE_OFF_T 1
#endif

#ifndef _UID_T_DEFINED
#define _UID_T_DEFINED
typedef int uid_t;
#endif
#ifndef HAVE_UID_T
#define HAVE_UID_T 1
#endif

#ifndef _GID_T_DEFINED
#define _GID_T_DEFINED
typedef int gid_t;
#endif
#ifndef HAVE_GID_T
#define HAVE_GID_T 1
#endif

#ifndef _UCHAR_T_DEFINED
#define _UCHAR_T_DEFINED
typedef unsigned char uchar;
#endif

/**
 * @brief File offset type.
 * MSVC defines this as long in sys/types.h under certain conditions.
 */
#ifndef _OFF_T_DEFINED
#define _OFF_T_DEFINED
typedef long long off_t;
#endif

/**
 * @brief 64-bit file offset type.
 * MSVC defines this as __int64.
 */
#ifndef _OFF64_T_DEFINED
#define _OFF64_T_DEFINED
typedef __int64 off64_t;
#endif

/**
 * @brief User ID type.
 * MSVC defines this as int.
 */
#ifndef _UID_T_DEFINED
#define _UID_T_DEFINED
typedef int uid_t;
#endif

/**
 * @brief Group ID type.
 * MSVC defines this as int.
 */
#ifndef _GID_T_DEFINED
#define _GID_T_DEFINED
typedef int gid_t;
#endif

/**
 * @brief Microseconds type.
 * MSVC defines this as unsigned int.
 */
#ifndef _USECONDS_T_DEFINED
#define _USECONDS_T_DEFINED
typedef unsigned int useconds_t;
#endif

/**
 * @brief Signed microseconds type.
 * MSVC defines this as long.
 */
#ifndef _SUSECONDS_T_DEFINED
#define _SUSECONDS_T_DEFINED
typedef long suseconds_t;
#endif

/**
 * @brief Device ID type.
 * MSVC defines this as unsigned int in sys/types.h.
 */
#ifndef _DEV_T_DEFINED
#define _DEV_T_DEFINED
typedef unsigned int dev_t;
#endif

/**
 * @brief Inode number type.
 * MSVC defines this as unsigned short in sys/types.h.
 */
#ifndef _INO_T_DEFINED
#define _INO_T_DEFINED
typedef unsigned short ino_t;
#endif

/**
 * @brief Number of hard links type.
 * MSVC defines this as short.
 */
#ifndef _NLINK_T_DEFINED
#define _NLINK_T_DEFINED
typedef short nlink_t;
#endif

/**
 * @brief Socket length type.
 * MSVC defines this as int.
 */
#ifndef _SOCKLEN_T_DEFINED
#define _SOCKLEN_T_DEFINED
typedef int socklen_t;
#endif

/**
 * @brief Socket address family type.
 * MSVC defines ADDRESS_FAMILY as unsigned short.
 */
#ifndef _SA_FAMILY_T_DEFINED
#define _SA_FAMILY_T_DEFINED
typedef unsigned short sa_family_t;
#endif

/**
 * @brief Signal set type.
 * MSVC defines this as unsigned long.
 */
#ifndef _SIGSET_T_DEFINED
#define _SIGSET_T_DEFINED
typedef unsigned long sigset_t;
#endif

/**
 * @brief Identifier type.
 * MSVC defines this as int.
 */
#ifndef _ID_T_DEFINED
#define _ID_T_DEFINED
typedef int id_t;
#endif

/**
 * @brief Inter-process communication key type.
 * MSVC defines this as int.
 */
#ifndef _KEY_T_DEFINED
#define _KEY_T_DEFINED
typedef int key_t;
#endif

/**
 * @brief Clock ticks type.
 * MSVC defines this as long.
 */
#ifndef _CLOCK_T_DEFINED
#define _CLOCK_T_DEFINED
typedef long clock_t;
#endif

/**
 * @brief Time in seconds type.
 * MSVC defines this as __time64_t.
 */
#ifndef _TIME_T_DEFINED
#define _TIME_T_DEFINED
typedef __time64_t time_t;
#endif

/**
 * @brief Timer type.
 * MSVC defines this as void*.
 */
#ifndef _TIMER_T_DEFINED
#define _TIMER_T_DEFINED
typedef void *timer_t;
#endif

/**
 * @brief Clock ID type.
 * MSVC defines this as int.
 */
#ifndef _CLOCKID_T_DEFINED
#define _CLOCKID_T_DEFINED
typedef int clockid_t;
#endif

/**
 * @brief File system block count type.
 * MSVC defines this as unsigned long long.
 */
#ifndef _FSBLKCNT_T_DEFINED
#define _FSBLKCNT_T_DEFINED
POSIX_TYPES_EXTENSION typedef unsigned long long fsblkcnt_t;
#endif

/**
 * @brief File system file count type.
 * MSVC defines this as unsigned long long.
 */
#ifndef _FSFILCNT_T_DEFINED
#define _FSFILCNT_T_DEFINED
POSIX_TYPES_EXTENSION typedef unsigned long long fsfilcnt_t;
#endif

/**
 * @brief Block size type.
 * MSVC defines this as long.
 */
#ifndef _BLKSIZE_T_DEFINED
#define _BLKSIZE_T_DEFINED
typedef long blksize_t;
#endif

/**
 * @brief Block count type.
 * MSVC defines this as long.
 */
#ifndef _BLKCNT_T_DEFINED
#define _BLKCNT_T_DEFINED
typedef long blkcnt_t;
#endif

#else /* ! _MSC_VER */

#include <sys/types.h>
#include <time.h>
#if !defined(_MSC_VER)
#include <unistd.h>
#endif

#ifdef __MINGW32__
#include <winsock2.h>
#include <ws2tcpip.h>
#elif defined(__MSDOS__) || defined(__WATCOMC__)
/* DOS has no sys/socket.h */
#else
#include <sys/socket.h>
/* clang-format on */

#ifdef __cplusplus
extern "C" {
#endif

#endif

#endif /* _MSC_VER */

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* POSIX_TYPES_H */
