/* posix-wait.h - Strict C89 Header */
#ifndef POSIX_WAIT_H
#define POSIX_WAIT_H

#if defined(_WIN32) || defined(__MSDOS__) || defined(__WATCOMC__)

/**
 * @brief PID type definition for Windows.
 */
#ifndef _PID_T_DEFINED
#define _PID_T_DEFINED
typedef int pid_t;
#endif

/**
 * @brief ID type definition for Windows.
 */
#ifndef _ID_T_DEFINED
#define _ID_T_DEFINED
typedef int id_t;
#endif

/**
 * @brief ID type enumeration.
 */
typedef enum { P_ALL, P_PID, P_PGID } idtype_t;

/**
 * @brief Signal info structure for waitid.
 */
#ifndef _SIGINFO_T_DEFINED
#define _SIGINFO_T_DEFINED
typedef struct {
  int si_signo;  /* Signal number */
  int si_code;   /* Signal code */
  int si_pid;    /* Sending process ID */
  int si_uid;    /* Real user ID of sending process */
  int si_status; /* Exit value or signal */
} siginfo_t;
#endif

/* Macros for waitpid */
#define WNOHANG 1
#define WUNTRACED 2
#define WCONTINUED 8

/* Macros for waitid */
#define WEXITED 4
#define WSTOPPED 2
#define WNOWAIT 0x01000000

/* POSIX wait status macros */
#define WIFEXITED(status) (((status) & 0x7F) == 0)
#define WEXITSTATUS(status) (((status) & 0xFF00) >> 8)
#define WIFSIGNALED(status)                                                    \
  (((status) & 0x7F) != 0 && ((status) & 0x7F) != 0x7F)
#define WTERMSIG(status) ((status) & 0x7F)
#define WIFSTOPPED(status) (((status) & 0xFF) == 0x7F)
/** \brief WSTOPSIG macro. */
#define WSTOPSIG(status) (((status) & 0xFF00) >> 8)

/**
 * @brief Waits for a child process to terminate.
 *
 * @param stat_loc Pointer to an integer where status information is stored.
 * @return The process ID of the terminated child, or -1 on error.
 */
pid_t wait(int *stat_loc);

/**
 * @brief Waits for a specific process or process group to terminate.
 *
 * @param pid The process ID or process group ID to wait for.
 * @param stat_loc Pointer to an integer where status information is stored.
 * @param options Options modifying wait behavior.
 * @return The process ID of the terminated child, 0 if WNOHANG and child
 * running, or -1 on error.
 */
pid_t waitpid(pid_t pid, int *stat_loc, int options);

/**
 * @brief Waits for a child process to change state.
 *
 * @param idtype The type of ID (P_ALL, P_PID, P_PGID).
 * @param id The ID to wait for.
 * @param infop Pointer to a siginfo_t structure where status information is
 * stored.
 * @param options Options modifying wait behavior.
 * @return 0 on success, or -1 on error.
 */
int waitid(idtype_t idtype, id_t id, siginfo_t *infop, int options);

/**
 * @brief Non-standard Microsoft-compatible cwait.
 *
 * @param termstat Pointer to store exit code.
 * @param pid Process ID to wait for.
 * @param action Unused on Windows (usually WAIT_CHILD).
 * @return The process ID of the terminated child.
 */
/* cwait removed */

#elif defined(__MSDOS__) || defined(__WATCOMC__)

/* DOS has no sys/wait.h */
#ifndef WNOHANG
#define WNOHANG 1
#endif
#ifndef WUNTRACED
#define WUNTRACED 2
#endif
#ifndef WEXITSTATUS
#define WEXITSTATUS(w) (((w) >> 8) & 0xff)
#endif
#ifndef WIFEXITED
#define WIFEXITED(w) (((w) & 0xff) == 0)
#endif

#else /* _WIN32 */

/* For non-Windows environments (like Darwin/Linux testing), include native
 * headers */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
/* clang-format off */
#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>
/* clang-format on */

#ifdef __cplusplus
extern "C" {
#endif

#ifdef __CYGWIN__
#ifndef _IDTYPE_T_DEFINED
#define _IDTYPE_T_DEFINED
typedef enum { P_ALL, P_PID, P_PGID } idtype_t;
#endif

#ifndef WEXITED
#define WEXITED 4
#endif
#ifndef WSTOPPED
#define WSTOPPED 2
#endif
#ifndef WNOWAIT
#define WNOWAIT 0x01000000
#endif
#endif /* __CYGWIN__ */

#ifdef __CYGWIN__
/**
 * @brief Waits for a child process to change state (Cygwin polyfill).
 *
 * @param idtype The type of ID (P_ALL, P_PID, P_PGID).
 * @param id The ID to wait for.
 * @param infop Pointer to a siginfo_t structure where status information is
 * stored.
 * @param options Options modifying wait behavior.
 * @return 0 on success, or -1 on error.
 */
int waitid(idtype_t idtype, id_t id, siginfo_t *infop, int options);
#endif

/**
 * @brief Non-standard Microsoft-compatible cwait.
 *
 * @param termstat Pointer to store exit code.
 * @param pid Process ID to wait for.
 * @param action Unused on Windows (usually WAIT_CHILD).
 * @return The process ID of the terminated child.
 */
/* cwait removed */

#endif /* _WIN32 */

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* POSIX_WAIT_H */
