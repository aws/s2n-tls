/* posix-signal.h - Strict C89 Implementation */
#ifndef POSIX_SIGNAL_H
#define POSIX_SIGNAL_H

#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
/* clang-format off */
#include <signal.h>
#include <stddef.h>
/* clang-format on */

#ifdef __cplusplus
extern "C" {
#endif

#if defined(_MSC_VER) && !defined(__clang__)
#define POSIX_SIGNAL_MSVC 1
#endif

#if defined(POSIX_SIGNAL_MSVC) || defined(_WIN32) || defined(__MSDOS__) ||     \
    defined(__WATCOMC__)

typedef unsigned long sigset_t;

#ifndef _PID_T_DEFINED
#define _PID_T_DEFINED
typedef int pid_t;
#endif

#ifndef _UID_T_DEFINED
#define _UID_T_DEFINED
typedef int uid_t;
typedef int gid_t;
#endif

#ifndef _SIGINFO_T_DEFINED
#define _SIGINFO_T_DEFINED
typedef struct {
  int si_signo;
  int si_code;
  int si_errno;
  pid_t si_pid;
  uid_t si_uid;
  void *si_addr;
  int si_status;
  long si_band;
} siginfo_t;
#endif

#ifndef SA_SIGINFO
#define SA_SIGINFO 0x00000004
#endif

struct sigaction {
  void (*sa_handler)(int);
  void (*sa_sigaction)(int, siginfo_t *, void *);
  sigset_t sa_mask;
  int sa_flags;
  void (*sa_restorer)(void);
};

/** \brief posix_signal_sigemptyset function. */
int posix_signal_sigemptyset(sigset_t *set);
/** \brief posix_signal_sigfillset function. */
int posix_signal_sigfillset(sigset_t *set);
/** \brief posix_signal_sigaddset function. */
int posix_signal_sigaddset(sigset_t *set, int signum);
/** \brief posix_signal_sigaction function. */
int posix_signal_sigaction(int signum, const struct sigaction *act,
                           struct sigaction *oldact);
/** \brief posix_signal_sigdelset function. */
int posix_signal_sigdelset(sigset_t *set, int signum);
/** \brief posix_signal_sigismember function. */
int posix_signal_sigismember(const sigset_t *set, int signum);
/** \brief posix_signal_sigprocmask function. */
int posix_signal_sigprocmask(int how, const sigset_t *set, sigset_t *oldset);
/** \brief posix_signal_sigpending function. */
int posix_signal_sigpending(sigset_t *set);
/** \brief posix_signal_sigsuspend function. */
int posix_signal_sigsuspend(const sigset_t *mask);
/** \brief posix_signal_kill function. */
int posix_signal_kill(pid_t pid, int sig);

#ifndef SIG_BLOCK
#define SIG_BLOCK 0
#define SIG_UNBLOCK 1
#define SIG_SETMASK 2
#endif

#ifndef sigemptyset
#define sigemptyset posix_signal_sigemptyset
#endif
#ifndef sigfillset
#define sigfillset posix_signal_sigfillset
#endif
#ifndef sigaddset
#define sigaddset posix_signal_sigaddset
#endif
#ifndef sigdelset
#define sigdelset posix_signal_sigdelset
#endif
#ifndef sigismember
#define sigismember posix_signal_sigismember
#endif
#ifndef sigprocmask
#define sigprocmask posix_signal_sigprocmask
#endif
#ifndef sigpending
#define sigpending posix_signal_sigpending
#endif
#ifndef sigsuspend
#define sigsuspend posix_signal_sigsuspend
#endif
#ifndef sigaction
#define sigaction(sig, act, oact) posix_signal_sigaction((sig), (act), (oact))
#endif
#ifndef kill
#define kill posix_signal_kill
#endif

#endif

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* POSIX_SIGNAL_H */
