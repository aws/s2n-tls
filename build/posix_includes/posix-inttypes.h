#ifndef POSIX_INTTYPES_H
#define POSIX_INTTYPES_H

/* Polyfill for <inttypes.h> */

#if defined(_MSC_VER)

#if _MSC_VER < 1800

/* clang-format off */
#include <posix-stdint.h>
#include <stdlib.h>

#ifndef PRId8
#define PRId8 "d"
#endif
#ifndef PRId16
#define PRId16 "d"
#endif
#ifndef PRId32
#define PRId32 "d"
#endif
#ifndef PRId64
#define PRId64 "I64d"
#endif

#ifndef PRIi8
#define PRIi8 "i"
#endif
#ifndef PRIi16
#define PRIi16 "i"
#endif
#ifndef PRIi32
#define PRIi32 "i"
#endif
#ifndef PRIi64
#define PRIi64 "I64i"
#endif

#ifndef PRIo8
#define PRIo8 "o"
#endif
#ifndef PRIo16
#define PRIo16 "o"
#endif
#ifndef PRIo32
#define PRIo32 "o"
#endif
#ifndef PRIo64
#define PRIo64 "I64o"
#endif

#ifndef PRIu8
#define PRIu8 "u"
#endif
#ifndef PRIu16
#define PRIu16 "u"
#endif
#ifndef PRIu32
#define PRIu32 "u"
#endif
#ifndef PRIu64
#define PRIu64 "I64u"
#endif

#ifndef PRIx8
#define PRIx8 "x"
#endif
#ifndef PRIx16
#define PRIx16 "x"
#endif
#ifndef PRIx32
#define PRIx32 "x"
#endif
#ifndef PRIx64
#define PRIx64 "I64x"
#endif

#ifndef PRIX8
#define PRIX8 "X"
#endif
#ifndef PRIX16
#define PRIX16 "X"
#endif
#ifndef PRIX32
#define PRIX32 "X"
#endif
#ifndef PRIX64
#define PRIX64 "I64X"
#endif

#define strtoimax _strtoi64
#define strtoumax _strtoui64

#else /* _MSC_VER >= 1800 */
#include <inttypes.h>
#endif /* _MSC_VER < 1800 */

#else /* !_MSC_VER */
#include <inttypes.h>
/* clang-format on */

#ifdef __cplusplus
extern "C" {
#endif

#endif

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* POSIX_INTTYPES_H */
