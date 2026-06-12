#ifndef BSD_SYS_SYSCTL_H
#define BSD_SYS_SYSCTL_H

/* clang-format off */
#if defined(_WIN32)
#include <stddef.h>
/* clang-format on */

#ifdef __cplusplus
extern "C" {
#endif

#define CTL_KERN 1
#define CTL_VM 2
#define CTL_VFS 3
#define CTL_NET 4
#define CTL_DEBUG 5
#define CTL_HW 6
#define CTL_MACHDEP 7
#define CTL_USER 8
#define CTL_P1003_1B 9

/* CTL_HW identifiers */
#define HW_MACHINE 1
#define HW_MODEL 2
#define HW_NCPU 3
#define HW_BYTEORDER 4
#define HW_PHYSMEM 5
#define HW_USERMEM 6
#define HW_PAGESIZE 7
#define HW_DISKNAMES 8
#define HW_DISKSTATS 9
#define HW_FLOATINGPT 10
#define HW_MACHINE_ARCH 11
#define HW_REALMEM 12
#define HW_MEMSIZE 24

/* CTL_KERN identifiers */
#define KERN_OSTYPE 1
#define KERN_OSRELEASE 2
#define KERN_OSREV 3
#define KERN_VERSION 4
#define KERN_MAXVNODES 5
#define KERN_MAXPROC 6
#define KERN_MAXFILES 7
#define KERN_ARGMAX 8
#define KERN_SECURELVL 9
#define KERN_HOSTNAME 10
#define KERN_HOSTID 11
#define KERN_CLOCKRATE 12
#define KERN_VNODE 13
#define KERN_PROC 14
#define KERN_FILE 15
#define KERN_PROF 16
#define KERN_POSIX1 17
#define KERN_NGROUPS 18
#define KERN_JOB_CONTROL 19
#define KERN_SAVED_IDS 20
#define KERN_BOOTTIME 21
#define KERN_IPC 22

/* KERN_IPC identifiers */
#define KIPC_SOMAXCONN 2

/* Custom CTL_VM */
#define VM_OVERCOMMIT 3

/** \brief sysctl function.
 *
 * Implements the sysctl POSIX interface for Windows.
 *
 * \param name Array of integers specifying the information to get/set.
 * \param namelen Number of integers in the name array.
 * \param oldp Pointer to buffer where information is returned.
 * \param oldlenp Pointer to size of oldp buffer.
 * \param newp Pointer to buffer with new information.
 * \param newlen Size of newp buffer.
 * \return 0 on success, or -1 on error with errno set.
 */
int sysctl(const int *name, unsigned int namelen, void *oldp, size_t *oldlenp,
           const void *newp, size_t newlen);

/** \brief sysctlbyname function.
 *
 * Implements the sysctlbyname interface for Windows.
 *
 * \param name String specifying the information to get/set.
 * \param oldp Pointer to buffer where information is returned.
 * \param oldlenp Pointer to size of oldp buffer.
 * \param newp Pointer to buffer with new information.
 * \param newlen Size of newp buffer.
 * \return 0 on success, or -1 on error with errno set.
 */
int sysctlbyname(const char *name, void *oldp, size_t *oldlenp,
                 const void *newp, size_t newlen);

#endif /* _WIN32 */

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
