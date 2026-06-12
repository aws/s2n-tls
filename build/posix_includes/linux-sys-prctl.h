
#ifdef __cplusplus
extern "C" {
#endif

#ifndef LINUX_SYS_PRCTL_H
#define LINUX_SYS_PRCTL_H

#if defined(_MSC_VER) && !defined(__clang__)

/** \brief Option to set the name of the calling thread. */
#define PR_SET_NAME 15

/** \brief Option to receive a signal when the parent process dies. */
#define PR_SET_PDEATHSIG 1

/** \brief Option to get the current parent death signal. */
#define PR_GET_PDEATHSIG 2

/** \brief prctl function.
 *
 * Implements process control operations.
 * Currently supports PR_SET_NAME to set the calling thread's name.
 *
 * \param option The operation to perform.
 * \param ... Variable arguments based on the option.
 * \return 0 on success, or -1 on error with errno set.
 */
int prctl(int option, ...);
#endif

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
