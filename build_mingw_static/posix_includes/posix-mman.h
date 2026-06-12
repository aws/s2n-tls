/* posix-mman.h - Strict C89 Header */
#ifndef POSIX_MMAN_H
#define POSIX_MMAN_H

#if !defined(_WIN32) && !defined(_WIN64) && !defined(__MSDOS__) &&             \
    !defined(__WATCOMC__)

/* Fallback to system mman on POSIX platforms */
/* clang-format off */
#include <sys/mman.h>

#if defined(__CYGWIN__)
#ifndef MCL_CURRENT
#define MCL_CURRENT 0x01
#endif
#ifndef MCL_FUTURE
#define MCL_FUTURE 0x02
#endif

/** \brief mlockall function. */
int mlockall(int flags);
/** \brief munlockall function. */
int munlockall(void);
#endif

#else

#include <stddef.h>
#include <sys/types.h>
/* clang-format on */

#ifdef __cplusplus
extern "C" {
#endif

/* Protection flags */
#ifndef PROT_NONE
#define PROT_NONE 0x00
#endif
#ifndef PROT_READ
#define PROT_READ 0x01
#endif
#ifndef PROT_WRITE
#define PROT_WRITE 0x02
#endif
#ifndef PROT_EXEC
#define PROT_EXEC 0x04
#endif

/* Mapping flags */
#ifndef MAP_SHARED
#define MAP_SHARED 0x01
#endif
#ifndef MAP_PRIVATE
#define MAP_PRIVATE 0x02
#endif
#ifndef MAP_FIXED
#define MAP_FIXED 0x10
#endif
#ifndef MAP_ANONYMOUS
#define MAP_ANONYMOUS 0x20
#endif
#ifndef MAP_ANON
#define MAP_ANON MAP_ANONYMOUS
#endif
#ifndef MAP_FAILED
/** \brief MAP_FAILED macro. */
#define MAP_FAILED ((void *)(size_t)-1)
#endif

/* msync flags */
#ifndef MS_ASYNC
#define MS_ASYNC 0x01
#endif
#ifndef MS_SYNC
#define MS_SYNC 0x02
#endif
#ifndef MS_INVALIDATE
#define MS_INVALIDATE 0x04
#endif

/* madvise advice flags */
#ifndef MADV_NORMAL
#define MADV_NORMAL 0
#endif
#ifndef MADV_RANDOM
#define MADV_RANDOM 1
#endif
#ifndef MADV_SEQUENTIAL
#define MADV_SEQUENTIAL 2
#endif
#ifndef MADV_WILLNEED
#define MADV_WILLNEED 3
#endif
#ifndef MADV_DONTNEED
#define MADV_DONTNEED 4
#endif
#ifndef MADV_FREE
#define MADV_FREE 8
#endif
#ifndef MADV_DONTDUMP
#define MADV_DONTDUMP 16
#endif

/* mlockall flags */
#ifndef MCL_CURRENT
#define MCL_CURRENT 0x01
#endif
#ifndef MCL_FUTURE
#define MCL_FUTURE 0x02
#endif

/* Windows mode_t polyfill if needed */
#if !defined(_MODE_T_) && !defined(__WATCOMC__) && !defined(_MODE_T_DEFINED_)
#define _MODE_T_
#define _MODE_T_DEFINED_
typedef unsigned short mode_t;
#endif

/*
 * madvise - give advice about use of memory
 * @addr: starting address
 * @length: length of the memory region
 * @advice: advice to give
 * Returns 0 on success, -1 on failure.
 */
/** \brief madvise function. */
int madvise(void *addr, size_t length, int advice);

/*
 * mlock - lock a range of process address space
 * @addr: starting address
 * @len: length of the memory to lock
 * Returns 0 on success, -1 on failure.
 */
/** \brief mlock function. */
int mlock(const void *addr, size_t len);

/*
 * mlockall - lock all process address space
 * @flags: MCL_CURRENT and/or MCL_FUTURE
 * Returns 0 on success, -1 on failure.
 */
/** \brief mlockall function. */
int mlockall(int flags);

/*
 * mmap - map files or devices into memory
 * @addr: starting address (hint)
 * @length: length of the mapping
 * @prot: protection flags (PROT_READ, PROT_WRITE, etc.)
 * @flags: mapping flags (MAP_SHARED, MAP_PRIVATE, etc.)
 * @fd: file descriptor
 * @offset: offset within the file
 * Returns mapped address on success, MAP_FAILED on failure.
 */
/** \brief mmap function. */
void *mmap(void *addr, size_t length, int prot, int flags, int fd,
           off_t offset);

/*
 * mprotect - set protection on a region of memory
 * @addr: starting address
 * @len: length of the region
 * @prot: protection flags
 * Returns 0 on success, -1 on failure.
 */
/** \brief mprotect function. */
int mprotect(void *addr, size_t len, int prot);

/*
 * msync - synchronize a file with a memory map
 * @addr: starting address
 * @length: length of the region
 * @flags: MS_SYNC, MS_ASYNC, MS_INVALIDATE
 * Returns 0 on success, -1 on failure.
 */
/** \brief msync function. */
int msync(void *addr, size_t length, int flags);

/*
 * munlock - unlock a range of process address space
 * @addr: starting address
 * @len: length of the memory to unlock
 * Returns 0 on success, -1 on failure.
 */
/** \brief munlock function. */
int munlock(const void *addr, size_t len);

/*
 * munlockall - unlock all process address space
 * Returns 0 on success, -1 on failure.
 */
/** \brief munlockall function. */
int munlockall(void);

/*
 * munmap - unmap files or devices
 * @addr: starting address
 * @length: length of the mapping
 * Returns 0 on success, -1 on failure.
 */
/** \brief munmap function. */
int munmap(void *addr, size_t length);

/*
 * shm_open - open a shared memory object
 * @name: name of the object
 * @oflag: open flags
 * @mode: file mode
 * Returns file descriptor on success, -1 on failure.
 */
/** \brief shm_open function. */
int shm_open(const char *name, int oflag, mode_t mode);

/*
 * shm_unlink - remove a shared memory object
 * @name: name of the object
 * Returns 0 on success, -1 on failure.
 */
/** \brief shm_unlink function. */
int shm_unlink(const char *name);

#endif /* _WIN32 */

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* POSIX_MMAN_H */
