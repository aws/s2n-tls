#ifndef POSIX_STDBOOL_H
#define POSIX_STDBOOL_H

/* Polyfill for <stdbool.h> */

#if defined(_MSC_VER) && _MSC_VER < 1800
#ifndef __cplusplus
#define bool unsigned char
#define true 1
#define false 0
#define __bool_true_false_are_defined 1
#endif /* !__cplusplus */
#else
/* For newer MSVC and GCC/Clang */
/* clang-format off */
#if !defined(_MSC_VER) || _MSC_VER >= 1800
#include <stdbool.h>
#endif
/* clang-format on */
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* No functions to declare */

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* POSIX_STDBOOL_H */
