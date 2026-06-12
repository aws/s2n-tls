#ifndef LINUX_BACKTRACE_H
#define LINUX_BACKTRACE_H

/* Polyfill for <backtrace.h> */
/* clang-format off */
#if defined(_MSC_VER) && _MSC_VER < 1600
#include <stddef.h>
#ifndef _UINTPTR_T_DEFINED
#ifdef _WIN64
typedef unsigned __int64 uintptr_t;
#else
typedef unsigned int uintptr_t;
#endif
#define _UINTPTR_T_DEFINED
#endif
#else
#if !defined(_MSC_VER) || _MSC_VER >= 1600
#include <stdint.h>
#endif
#endif
/* clang-format on */

#ifdef __cplusplus
extern "C" {
#endif

/* Dummy state structure */
struct backtrace_state;

typedef void (*backtrace_error_callback)(void *data, const char *msg,
                                         int errnum);
typedef int (*backtrace_full_callback)(void *data, uintptr_t pc,
                                       const char *filename, int lineno,
                                       const char *function);

static __inline struct backtrace_state *
backtrace_create_state(const char *filename, int threaded,
                       backtrace_error_callback error_callback, void *data) {
  (void)filename;
  (void)threaded;
  (void)error_callback;
  (void)data;
  return 0;
}

/** \brief backtrace_pcinfo function. */
static __inline int backtrace_pcinfo(struct backtrace_state *state,
                                     uintptr_t pc,
                                     backtrace_full_callback callback,
                                     backtrace_error_callback error_callback,
                                     void *data) {
  (void)state;
  (void)pc;
  (void)callback;
  (void)error_callback;
  (void)data;
  return 0;
}

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* LINUX_BACKTRACE_H */
