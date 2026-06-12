#ifndef BSD_MACHINE_ENDIAN_H
#define BSD_MACHINE_ENDIAN_H

/* Polyfill for <machine/endian.h> */

#if defined(_MSC_VER)
/* We defer to the standard endian.h polyfill which provides the necessary
 * macros */
/* clang-format off */
#include <linux-endian.h>
/* clang-format on */
#endif /* _MSC_VER */

#ifdef __cplusplus
extern "C" {
#endif

/* function declarations if any */

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* BSD_MACHINE_ENDIAN_H */
