/* bsd-sys-param.h - Strict C89 Header */
#ifndef BSD_SYS_PARAM_H
#define BSD_SYS_PARAM_H

/**
 * @file bsd-sys-param.h
 * @brief POSIX sys/param.h implementation for MSVC
 *
 * This header defines common macros from sys/param.h,
 * mapped to their MSVC/Windows equivalents.
 */

#if defined(_MSC_VER) || defined(_WIN32) || defined(__WATCOMC__) ||            \
    defined(__DOS__)

/* clang-format off */
#include <stdlib.h> /* _MAX_PATH */

/**
 * @brief Max length of a file path.
 */
#ifndef MAXPATHLEN
#ifdef _MAX_PATH
#define MAXPATHLEN _MAX_PATH
#else
#define MAXPATHLEN 260
#endif
#endif

/**
 * @brief Evaluates to the smaller of two elements.
 */
#ifndef MIN
#define MIN(a, b) (((a) < (b)) ? (a) : (b))
#endif

/**
 * @brief Evaluates to the larger of two elements.
 */
#ifndef MAX
#define MAX(a, b) (((a) > (b)) ? (a) : (b))
#endif

/**
 * @brief Returns the number of units y in x (ceiling division).
 */
#ifndef howmany
#define howmany(x, y) (((x) + ((y) - 1)) / (y))
#endif

/**
 * @brief Rounds x up to the nearest multiple of y.
 */
#ifndef roundup
#define roundup(x, y) ((((x) + ((y) - 1)) / (y)) * (y))
#endif

/**
 * @brief True if x is a power of 2, false otherwise.
 */
#ifndef powerof2
#define powerof2(x) ((((x) - 1) & (x)) == 0)
#endif

#else /* Not MSVC/Windows */

#include <sys/param.h>
/* clang-format on */

#ifdef __cplusplus
extern "C" {
#endif

#endif /* defined(_MSC_VER) || defined(_WIN32) || defined(__WATCOMC__) ||      \
          defined(__DOS__) */

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* BSD_SYS_PARAM_H */
