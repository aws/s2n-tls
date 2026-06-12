/* posix-pwdgrp.h - Strict C89 Header */
#ifndef POSIX_PWDGRP_H
#define POSIX_PWDGRP_H

/**
 * @file posix-pwdgrp.h
 * @brief POSIX user and group database access (pwd.h and grp.h) ported to MSVC.
 *
 * Provides polyfills and structures for reading user (passwd) and group
 * information on Windows systems, mimicking POSIX systems.
 */

/* clang-format off */
#include <stddef.h>

#ifdef _WIN32

#ifndef _UID_T_DEFINED
#define _UID_T_DEFINED
/** @brief POSIX user identifier type */
typedef unsigned int uid_t;
#endif

#ifndef _GID_T_DEFINED
#define _GID_T_DEFINED
/** @brief POSIX group identifier type */
typedef unsigned int gid_t;
#endif

/**
 * @struct passwd
 * @brief Structure containing user account information.
 */
struct passwd {
  char *pw_name;   /**< User's login name. */
  char *pw_passwd; /**< Unencrypted password (always empty or dummy on Windows).
                    */
  uid_t pw_uid;    /**< Numerical user ID (maps to Windows SID RID). */
  gid_t pw_gid;    /**< Numerical group ID. */
  char *pw_gecos;  /**< User name or comment. */
  char *pw_dir;    /**< Initial working directory (user profile path). */
  char *pw_shell;  /**< Program to use as shell. */
};

/**
 * @struct group
 * @brief Structure containing group account information.
 */
struct group {
  char *gr_name;   /**< The name of the group. */
  char *gr_passwd; /**< The password of the group (always empty or dummy). */
  gid_t gr_gid;    /**< Numerical group ID (maps to Windows SID RID). */
  char **gr_mem;   /**< Pointer to a null-terminated array of member names. */
};

/**
 * @brief Closes the group database.
 */
void endgrent(void);

/**
 * @brief Reads the next entry from the group database.
 * @return Pointer to a statically allocated group structure, or NULL on error
 * or EOF.
 */
struct group *getgrent(void);

/**
 * @brief Searches the group database for a group with the given ID.
 * @param gid The group ID to search for.
 * @return Pointer to a statically allocated group structure, or NULL on error.
 */
struct group *getgrgid(gid_t gid);

/**
 * @brief Thread-safe version of getgrgid.
 * @param gid The group ID to search for.
 * @param grp Pointer to the group structure to populate.
 * @param buffer Working buffer for strings.
 * @param bufsize Size of the working buffer.
 * @param result Pointer to the returned group pointer (NULL on error).
 * @return 0 on success, or an error number on failure.
 */
int getgrgid_r(gid_t gid, struct group *grp, char *buffer, size_t bufsize,
               struct group **result);

/**
 * @brief Searches the group database for a group with the given name.
 * @param name The group name to search for.
 * @return Pointer to a statically allocated group structure, or NULL on error.
 */
struct group *getgrnam(const char *name);

/**
 * @brief Thread-safe version of getgrnam.
 * @param name The group name to search for.
 * @param grp Pointer to the group structure to populate.
 * @param buffer Working buffer for strings.
 * @param bufsize Size of the working buffer.
 * @param result Pointer to the returned group pointer (NULL on error).
 * @return 0 on success, or an error number on failure.
 */
int getgrnam_r(const char *name, struct group *grp, char *buffer,
               size_t bufsize, struct group **result);

/**
 * @brief Rewinds the group database to the beginning.
 */
void setgrent(void);

/**
 * @brief Closes the user database.
 */
void endpwent(void);

/**
 * @brief Reads the next entry from the user database.
 * @return Pointer to a statically allocated passwd structure, or NULL on error
 * or EOF.
 */
struct passwd *getpwent(void);

/**
 * @brief Searches the user database for a user with the given name.
 * @param name The user name to search for.
 * @return Pointer to a statically allocated passwd structure, or NULL on error.
 */
struct passwd *getpwnam(const char *name);

/**
 * @brief Thread-safe version of getpwnam.
 * @param name The user name to search for.
 * @param pwd Pointer to the passwd structure to populate.
 * @param buffer Working buffer for strings.
 * @param bufsize Size of the working buffer.
 * @param result Pointer to the returned passwd pointer (NULL on error).
 * @return 0 on success, or an error number on failure.
 */
int getpwnam_r(const char *name, struct passwd *pwd, char *buffer,
               size_t bufsize, struct passwd **result);

/**
 * @brief Searches the user database for a user with the given ID.
 * @param uid The user ID to search for.
 * @return Pointer to a statically allocated passwd structure, or NULL on error.
 */
struct passwd *getpwuid(uid_t uid);

/**
 * @brief Thread-safe version of getpwuid.
 * @param uid The user ID to search for.
 * @param pwd Pointer to the passwd structure to populate.
 * @param buffer Working buffer for strings.
 * @param bufsize Size of the working buffer.
 * @param result Pointer to the returned passwd pointer (NULL on error).
 * @return 0 on success, or an error number on failure.
 */
int getpwuid_r(uid_t uid, struct passwd *pwd, char *buffer, size_t bufsize,
               struct passwd **result);

/**
 * @brief Rewinds the user database to the beginning.
 */
void setpwent(void);

#else /* _WIN32 */

#include <grp.h>
#include <pwd.h>
#include <sys/types.h>
/* clang-format on */

#ifdef __cplusplus
extern "C" {
#endif

#endif /* _WIN32 */

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* POSIX_PWDGRP_H */
