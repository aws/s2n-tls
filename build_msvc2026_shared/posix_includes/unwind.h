/* posix-unwind/include/unwind.h - Strict C89 Implementation */
#ifndef POSIX_UNWIND_H
#define POSIX_UNWIND_H

#if defined(__GNUC__) || defined(__clang__)
#pragma GCC system_header
/* clang-format off */
#include_next <unwind.h>
#else

#include <stddef.h>
/* clang-format on */

#ifdef __cplusplus
extern "C" {
#endif

/** \brief Reason code for unwind operations. */
typedef enum {
  _URC_NO_REASON = 0,
  _URC_FOREIGN_EXCEPTION_CAUGHT = 1,
  _URC_FATAL_PHASE2_ERROR = 2,
  _URC_FATAL_PHASE1_ERROR = 3,
  _URC_NORMAL_STOP = 4,
  _URC_END_OF_STACK = 5,
  _URC_HANDLER_FOUND = 6,
  _URC_INSTALL_CONTEXT = 7,
  _URC_CONTINUE_UNWIND = 8
} _Unwind_Reason_Code;

/** \brief Opaque structure representing an unwind context. */
struct _Unwind_Context;

/** \brief Trace function prototype. */
typedef _Unwind_Reason_Code (*_Unwind_Trace_Fn)(struct _Unwind_Context *,
                                                void *);

/**
 * @brief Get the instruction pointer from the context
 * @param context The unwind context
 * @return The instruction pointer
 */
size_t _Unwind_GetIP(struct _Unwind_Context *context);

/**
 * @brief Backtrace the stack
 * @param trace The trace function
 * @param trace_argument The trace argument
 * @return The reason code
 */
_Unwind_Reason_Code _Unwind_Backtrace(_Unwind_Trace_Fn trace,
                                      void *trace_argument);

#endif /* __GNUC__ || __clang__ */

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* POSIX_UNWIND_H */
