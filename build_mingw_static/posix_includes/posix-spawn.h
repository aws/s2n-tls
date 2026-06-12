/* posix-spawn.h - Strict C89 Header */
#ifndef POSIX_SPAWN_H
#define POSIX_SPAWN_H

/* clang-format off */
#include <stddef.h>

#if defined(_MSC_VER)
#include <sys/types.h>

#ifndef _PID_T_DEFINED
typedef int pid_t;
#define _PID_T_DEFINED
#endif

#if !defined(_MODE_T_DEFINED) && !defined(__WATCOMC__)
typedef unsigned short mode_t;
#define _MODE_T_DEFINED
#endif
#ifndef _SIGSET_T_DEFINED
typedef unsigned int sigset_t;
#define _SIGSET_T_DEFINED
#endif

#ifndef _SCHED_PARAM_DEFINED
struct sched_param {
  int sched_priority;
};
#define _SCHED_PARAM_DEFINED
#endif

#elif defined(__MINGW32__)
#include <sched.h>
#include <signal.h>
#include <sys/types.h>

#ifndef _SIGSET_T_DEFINED
typedef _sigset_t sigset_t;
#define _SIGSET_T_DEFINED
#endif

#elif defined(__MSDOS__) || defined(__WATCOMC__)

#ifndef _PID_T_DEFINED
typedef int pid_t;
#define _PID_T_DEFINED
#endif

#ifndef _MODE_T_DEFINED
typedef unsigned short mode_t;
#define _MODE_T_DEFINED
#endif

#ifndef _SIGSET_T_DEFINED
typedef unsigned long sigset_t;
#define _SIGSET_T_DEFINED
#endif

#ifndef _SCHED_PARAM_DEFINED
struct sched_param {
    int sched_priority;
};
#define _SCHED_PARAM_DEFINED
#endif

#else /* POSIX */

#include <sched.h>
#include <signal.h>
#include <sys/types.h>
/* clang-format on */

#ifdef __cplusplus
extern "C" {
#endif

#endif

/* Flags */
#define POSIX_SPAWN_RESETIDS 0x01
#define POSIX_SPAWN_SETPGROUP 0x02
#define POSIX_SPAWN_SETSIGDEF 0x04
#define POSIX_SPAWN_SETSIGMASK 0x08
#define POSIX_SPAWN_SETSCHEDPARAM 0x10
#define POSIX_SPAWN_SETSCHEDULER 0x20

/* Types */

/* Opaque struct for file actions */
typedef struct {
  void *actions;
} posix_spawn_file_actions_t;

/* Opaque struct for spawn attributes */
typedef struct {
  short flags;
  pid_t pgroup;
  struct sched_param schedparam;
  int schedpolicy;
  sigset_t sigmask;
  sigset_t sigdefault;
} posix_spawnattr_t;

/* Functions */

/**
 * @brief Spawn a new process
 * @param pid Pointer to store the PID of the newly spawned process
 * @param path Path to the executable
 * @param file_actions File actions to perform
 * @param attrp Attributes for the spawned process
 * @param argv Argument list
 * @param envp Environment list
 * @return 0 on success, error code on failure
 */
int posix_spawn(pid_t *pid, const char *path,
                const posix_spawn_file_actions_t *file_actions,
                const posix_spawnattr_t *attrp, char *const argv[],
                char *const envp[]);

/**
 * @brief Spawn a new process using the PATH environment variable
 * @param pid Pointer to store the PID of the newly spawned process
 * @param file Path to the executable (searched in PATH)
 * @param file_actions File actions to perform
 * @param attrp Attributes for the spawned process
 * @param argv Argument list
 * @param envp Environment list
 * @return 0 on success, error code on failure
 */
int posix_spawnp(pid_t *pid, const char *file,
                 const posix_spawn_file_actions_t *file_actions,
                 const posix_spawnattr_t *attrp, char *const argv[],
                 char *const envp[]);

/* File Actions */

/**
 * @brief Initialize a file actions object
 * @param file_actions Pointer to the file actions object to initialize
 * @return 0 on success, error code on failure
 */
int posix_spawn_file_actions_init(posix_spawn_file_actions_t *file_actions);

/**
 * @brief Destroy a file actions object
 * @param file_actions Pointer to the file actions object to destroy
 * @return 0 on success, error code on failure
 */
int posix_spawn_file_actions_destroy(posix_spawn_file_actions_t *file_actions);

/**
 * @brief Add a close action to the file actions object
 * @param file_actions Pointer to the file actions object
 * @param fildes File descriptor to close
 * @return 0 on success, error code on failure
 */
int posix_spawn_file_actions_addclose(posix_spawn_file_actions_t *file_actions,
                                      int fildes);

/**
 * @brief Add a dup2 action to the file actions object
 * @param file_actions Pointer to the file actions object
 * @param fildes Source file descriptor
 * @param newfildes Target file descriptor
 * @return 0 on success, error code on failure
 */
int posix_spawn_file_actions_adddup2(posix_spawn_file_actions_t *file_actions,
                                     int fildes, int newfildes);

/**
 * @brief Add an open action to the file actions object
 * @param file_actions Pointer to the file actions object
 * @param fildes File descriptor to open
 * @param path Path to the file to open
 * @param oflag Open flags
 * @param mode File mode
 * @return 0 on success, error code on failure
 */
int posix_spawn_file_actions_addopen(posix_spawn_file_actions_t *file_actions,
                                     int fildes, const char *path, int oflag,
                                     mode_t mode);

/* Attributes */

/**
 * @brief Initialize a spawn attributes object
 * @param attr Pointer to the attributes object to initialize
 * @return 0 on success, error code on failure
 */
int posix_spawnattr_init(posix_spawnattr_t *attr);

/**
 * @brief Destroy a spawn attributes object
 * @param attr Pointer to the attributes object to destroy
 * @return 0 on success, error code on failure
 */
int posix_spawnattr_destroy(posix_spawnattr_t *attr);

/**
 * @brief Get the spawn flags from a spawn attributes object
 * @param attr Pointer to the attributes object
 * @param flags Pointer to store the flags
 * @return 0 on success, error code on failure
 */
int posix_spawnattr_getflags(const posix_spawnattr_t *attr, short *flags);

/**
 * @brief Set the spawn flags in a spawn attributes object
 * @param attr Pointer to the attributes object
 * @param flags The flags to set
 * @return 0 on success, error code on failure
 */
int posix_spawnattr_setflags(posix_spawnattr_t *attr, short flags);

/**
 * @brief Get the process group ID from a spawn attributes object
 * @param attr Pointer to the attributes object
 * @param pgroup Pointer to store the process group ID
 * @return 0 on success, error code on failure
 */
int posix_spawnattr_getpgroup(const posix_spawnattr_t *attr, pid_t *pgroup);

/**
 * @brief Set the process group ID in a spawn attributes object
 * @param attr Pointer to the attributes object
 * @param pgroup The process group ID to set
 * @return 0 on success, error code on failure
 */
int posix_spawnattr_setpgroup(posix_spawnattr_t *attr, pid_t pgroup);

/**
 * @brief Get the scheduling parameters from a spawn attributes object
 * @param attr Pointer to the attributes object
 * @param schedparam Pointer to store the scheduling parameters
 * @return 0 on success, error code on failure
 */
int posix_spawnattr_getschedparam(const posix_spawnattr_t *attr,
                                  struct sched_param *schedparam);

/**
 * @brief Set the scheduling parameters in a spawn attributes object
 * @param attr Pointer to the attributes object
 * @param schedparam Pointer to the scheduling parameters to set
 * @return 0 on success, error code on failure
 */
int posix_spawnattr_setschedparam(posix_spawnattr_t *attr,
                                  const struct sched_param *schedparam);

/**
 * @brief Get the scheduling policy from a spawn attributes object
 * @param attr Pointer to the attributes object
 * @param schedpolicy Pointer to store the scheduling policy
 * @return 0 on success, error code on failure
 */
int posix_spawnattr_getschedpolicy(const posix_spawnattr_t *attr,
                                   int *schedpolicy);

/**
 * @brief Set the scheduling policy in a spawn attributes object
 * @param attr Pointer to the attributes object
 * @param schedpolicy The scheduling policy to set
 * @return 0 on success, error code on failure
 */
int posix_spawnattr_setschedpolicy(posix_spawnattr_t *attr, int schedpolicy);

/**
 * @brief Get the default signal mask from a spawn attributes object
 * @param attr Pointer to the attributes object
 * @param sigdefault Pointer to store the default signal mask
 * @return 0 on success, error code on failure
 */
int posix_spawnattr_getsigdefault(const posix_spawnattr_t *attr,
                                  sigset_t *sigdefault);

/**
 * @brief Set the default signal mask in a spawn attributes object
 * @param attr Pointer to the attributes object
 * @param sigdefault Pointer to the default signal mask to set
 * @return 0 on success, error code on failure
 */
int posix_spawnattr_setsigdefault(posix_spawnattr_t *attr,
                                  const sigset_t *sigdefault);

/**
 * @brief Get the signal mask from a spawn attributes object
 * @param attr Pointer to the attributes object
 * @param sigmask Pointer to store the signal mask
 * @return 0 on success, error code on failure
 */
int posix_spawnattr_getsigmask(const posix_spawnattr_t *attr,
                               sigset_t *sigmask);

/**
 * @brief Set the signal mask in a spawn attributes object
 * @param attr Pointer to the attributes object
 * @param sigmask Pointer to the signal mask to set
 * @return 0 on success, error code on failure
 */
int posix_spawnattr_setsigmask(posix_spawnattr_t *attr,
                               const sigset_t *sigmask);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* POSIX_SPAWN_H */
