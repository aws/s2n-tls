/* posix-signal-ext.h - Strict C89 Implementation */
#ifndef POSIX_SIGNAL_EXT_H
#define POSIX_SIGNAL_EXT_H

/* clang-format off */
#include "posix-signal.h"
/* clang-format on */

#ifdef __cplusplus
extern "C" {
#endif

#if defined(POSIX_SIGNAL_MSVC)

#ifndef SA_NOCLDSTOP
#define SA_NOCLDSTOP 1
#endif
#ifndef SA_NOCLDWAIT
#define SA_NOCLDWAIT 2
#endif
#ifndef SA_SIGINFO
#define SA_SIGINFO 4
#endif
#ifndef SA_ONSTACK
#define SA_ONSTACK 0x08000000
#endif
#ifndef SA_RESTART
#define SA_RESTART 0x10000000
#endif
#ifndef SA_NODEFER
#define SA_NODEFER 0x40000000
#endif
#ifndef SA_RESETHAND
#define SA_RESETHAND 0x80000000
#endif

#ifndef SIGPIPE
#define SIGPIPE 13
#endif
#ifndef SIGALRM
#define SIGALRM 14
#endif
#ifndef SIGCHLD
#define SIGCHLD 17
#endif
#ifndef SIGQUIT
#define SIGQUIT 3
#endif
#ifndef SIGTRAP
#define SIGTRAP 5
#endif
#ifndef SIGHUP
#define SIGHUP 1
#endif
#ifndef SIGUSR1
#define SIGUSR1 10
#endif
#ifndef SIGUSR2
#define SIGUSR2 12
#endif

#endif /* POSIX_SIGNAL_MSVC */

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* POSIX_SIGNAL_EXT_H */
