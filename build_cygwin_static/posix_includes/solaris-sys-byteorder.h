#ifndef SOLARIS_SYS_BYTEORDER_H
#define SOLARIS_SYS_BYTEORDER_H

/* Polyfill for <sys/byteorder.h> */

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

#endif /* SOLARIS_SYS_BYTEORDER_H */
