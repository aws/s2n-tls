#if defined(__GNUC__)
#pragma GCC system_header
#endif
/* clang-format off */
#if !defined(_WIN32)
#if defined(__GNUC__) || defined(__clang__)
#include_next <termios.h>
#else
#include <termios.h>
#endif
#else
#include "posix-termios.h"
/* clang-format on */

#ifdef __cplusplus
extern "C" {
#endif

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
