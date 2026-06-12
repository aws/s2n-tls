#if defined(__GNUC__)
#pragma GCC system_header
#endif
/* clang-format off */
#if !defined(_WIN32)
#if defined(__GNUC__) || defined(__clang__)
#include_next <dirent.h>
#else
#include <dirent.h>
#endif
#else
#include "posix-dirent.h"
/* clang-format on */

#ifdef __cplusplus
extern "C" {
#endif

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
