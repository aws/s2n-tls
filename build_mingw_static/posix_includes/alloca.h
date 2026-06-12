/* alloca.h - Strict C89 Implementation */
#ifndef POSIX_ALLOCA_H
#define POSIX_ALLOCA_H

#if defined(_MSC_VER) || defined(__WATCOMC__) || defined(__MSDOS__) ||         \
    defined(__MINGW32__)
/* clang-format off */
#include <malloc.h>
#if defined(_MSC_VER) && !defined(alloca)
#define alloca _alloca
#endif
#else
#include <stdlib.h>
/* clang-format on */
#if defined(__GNUC__) || defined(__clang__)
#ifndef alloca
#define alloca __builtin_alloca
#endif
#endif
#endif

#ifdef __cplusplus
extern "C" {
#endif

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* POSIX_ALLOCA_H */
