#if defined(__GNUC__)
#pragma GCC system_header
#endif
/* clang-format off */
#if !defined(_WIN32)
#if defined(__GNUC__) || defined(__clang__)
#include_next <syslog.h>
#else
#include <syslog.h>
#endif
#else
#include "posix-syslog.h"
/* clang-format on */

#ifdef __cplusplus
extern "C" {
#endif

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
