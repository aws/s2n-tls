#ifndef BSD_SYS_ENDIAN_H
#define BSD_SYS_ENDIAN_H

/* Polyfill for <sys/endian.h> */

/* clang-format off */
#if defined(_MSC_VER)
#include <linux-endian.h>
/* clang-format on */

#ifdef __cplusplus
extern "C" {
#endif

#endif

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* BSD_SYS_ENDIAN_H */
