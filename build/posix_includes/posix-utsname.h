
#ifdef __cplusplus
extern "C" {
#endif

/**
 * @file posix-utsname.h
 * @brief POSIX sys/utsname.h compatibility layer for MSVC.
 */
#ifndef POSIX_UTSNAME_H
#define POSIX_UTSNAME_H

/**
 * @def _UTSNAME_LENGTH
 * @brief Length of the strings in struct utsname.
 *
 * Defines the maximum length of the character arrays in struct utsname,
 * including the terminating null byte.
 */
#ifndef _UTSNAME_LENGTH
#define _UTSNAME_LENGTH 256
#endif

/**
 * @struct utsname
 * @brief Structure describing the system and machine.
 *
 * This structure is populated by the uname() function with information
 * about the current operating system and hardware.
 */
struct utsname {
  char sysname[_UTSNAME_LENGTH];  /**< Name of the operating system
                                     implementation. */
  char nodename[_UTSNAME_LENGTH]; /**< Network name of this machine. */
  char release[_UTSNAME_LENGTH];  /**< Current release level of the operating
                                     system. */
  char version[_UTSNAME_LENGTH];  /**< Current version level of the operating
                                     system. */
  char machine[_UTSNAME_LENGTH];  /**< Hardware type/architecture. */
};

/**
 * @brief Get system identification.
 *
 * Populates the provided utsname structure with system information.
 *
 * @param name Pointer to a utsname structure to be filled.
 * @return 0 on success, or -1 on error (with errno set appropriately).
 */
int uname(struct utsname *name);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* POSIX_UTSNAME_H */
