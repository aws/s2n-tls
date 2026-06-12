/* posix-stat.h - Strict C89 Header */
#ifndef POSIX_STAT_H
#define POSIX_STAT_H

/* clang-format off */
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>

#ifdef _WIN32
#include <direct.h>
#if defined(_MSC_VER) && _MSC_VER >= 1900
#include <../ucrt/io.h>
#else
#include <io.h>
#endif
#else
#include <fcntl.h>
#if !defined(_MSC_VER)
#include <unistd.h>
#endif
/* clang-format on */

#ifdef __cplusplus
extern "C" {
#endif

#endif

#ifdef _WIN32
/* Standard Types (if missing) */
#ifndef _MODE_T_DEFINED
#define _MODE_T_DEFINED
typedef unsigned short mode_t;
#endif

/* POSIX timespec */
#if !defined(_TIMESPEC_DEFINED) && !defined(HAVE_STRUCT_TIMESPEC)
#if defined(_MSC_VER) && _MSC_VER >= 1900
/* VS2015+ provides struct timespec in time.h */
#else
#define _TIMESPEC_DEFINED
struct timespec {
  time_t tv_sec;
  long tv_nsec;
};
#endif
#endif

/* Macros from mappings.json */
#ifndef S_IFMT
#define S_IFMT _S_IFMT
#endif
#ifndef S_IFDIR
#define S_IFDIR _S_IFDIR
#endif
#ifndef S_IFCHR
#define S_IFCHR _S_IFCHR
#endif
#ifndef S_IFREG
#define S_IFREG _S_IFREG
#endif
#ifndef S_IFIFO
#define S_IFIFO _S_IFIFO
#endif

#ifndef S_IRUSR
#define S_IRUSR _S_IREAD
#endif
#ifndef S_IWUSR
#define S_IWUSR _S_IWRITE
#endif
#ifndef S_IXUSR
#define S_IXUSR _S_IEXEC
#endif

/* Polyfill Macros */
#ifndef S_IFLNK
#define S_IFLNK 0120000
#endif
#ifndef S_IFSOCK
#define S_IFSOCK 0140000
#endif
#ifndef S_IFBLK
#define S_IFBLK 0060000
#endif

#ifndef S_IRWXU
/** \brief S_IRWXU macro. */
#define S_IRWXU (S_IRUSR | S_IWUSR | S_IXUSR)
#endif

#ifndef S_IRGRP
/** \brief S_IRGRP macro. */
#define S_IRGRP (S_IRUSR >> 3)
#endif
#ifndef S_IWGRP
/** \brief S_IWGRP macro. */
#define S_IWGRP (S_IWUSR >> 3)
#endif
#ifndef S_IXGRP
/** \brief S_IXGRP macro. */
#define S_IXGRP (S_IXUSR >> 3)
#endif
#ifndef S_IRWXG
/** \brief S_IRWXG macro. */
#define S_IRWXG (S_IRWXU >> 3)
#endif

#ifndef S_IROTH
/** \brief S_IROTH macro. */
#define S_IROTH (S_IRGRP >> 3)
#endif
#ifndef S_IWOTH
/** \brief S_IWOTH macro. */
#define S_IWOTH (S_IWGRP >> 3)
#endif
#ifndef S_IXOTH
/** \brief S_IXOTH macro. */
#define S_IXOTH (S_IXGRP >> 3)
#endif
#ifndef S_IRWXO
/** \brief S_IRWXO macro. */
#define S_IRWXO (S_IRWXG >> 3)
#endif

#ifndef S_ISDIR
/** \brief S_ISDIR macro. */
#define S_ISDIR(m) (((m) & S_IFMT) == S_IFDIR)
#endif
#ifndef S_ISCHR
/** \brief S_ISCHR macro. */
#define S_ISCHR(m) (((m) & S_IFMT) == S_IFCHR)
#endif
#ifndef S_ISREG
/** \brief S_ISREG macro. */
#define S_ISREG(m) (((m) & S_IFMT) == S_IFREG)
#endif
#ifndef S_ISFIFO
/** \brief S_ISFIFO macro. */
#define S_ISFIFO(m) (((m) & S_IFMT) == S_IFIFO)
#endif
#ifndef S_ISLNK
/** \brief S_ISLNK macro. */
#define S_ISLNK(m) (((m) & S_IFMT) == S_IFLNK)
#endif
#ifndef S_ISSOCK
/** \brief S_ISSOCK macro. */
#define S_ISSOCK(m) (((m) & S_IFMT) == S_IFSOCK)
#endif
#ifndef S_ISBLK
/** \brief S_ISBLK macro. */
#define S_ISBLK(m) (((m) & S_IFMT) == S_IFBLK)
#endif

/* Special values for utimensat / futimens */
#define UTIME_NOW ((1L << 30) - 1L)
#define UTIME_OMIT ((1L << 30) - 2L)

/* Flags for *at functions */
#define AT_FDCWD -100
#define AT_SYMLINK_NOFOLLOW 0x100

/* Function Shims */
#define stat _stat64
#define fstat _fstat64
#define chmod _chmod
#define umask _umask
#define mkdir(path, mode) _mkdir(path)

/* Functions requiring polyfill */
/** \brief fchmod function. */
int fchmod(int fd, mode_t mode);
/** \brief fchmodat function. */
int fchmodat(int dirfd, const char *pathname, mode_t mode, int flags);
/** \brief fstatat function. */
int fstatat(int dirfd, const char *pathname, struct _stat64 *statbuf,
            int flags);
/** \brief futimens function. */
int futimens(int fd, const struct timespec times[2]);
/** \brief lstat function. */
int lstat(const char *pathname, struct _stat64 *statbuf);
/** \brief mknod function. */
int mknod(const char *pathname, mode_t mode, unsigned int dev);
/** \brief mknodat function. */
int mknodat(int dirfd, const char *pathname, mode_t mode, unsigned int dev);
/** \brief utimensat function. */
int utimensat(int dirfd, const char *pathname, const struct timespec times[2],
              int flags);
#endif /* _WIN32 */

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* POSIX_STAT_H */
