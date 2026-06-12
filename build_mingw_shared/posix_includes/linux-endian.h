#ifndef LINUX_ENDIAN_H
#define LINUX_ENDIAN_H

/* clang-format off */
#if defined(_MSC_VER)
#include <stdlib.h>
/* clang-format on */
#endif /* _MSC_VER */

#ifdef __cplusplus
extern "C" {
#endif

#if defined(_MSC_VER)

#define __LITTLE_ENDIAN 1234
#define __BIG_ENDIAN 4321
#define __PDP_ENDIAN 3412

#define __BYTE_ORDER __LITTLE_ENDIAN
#define LITTLE_ENDIAN __LITTLE_ENDIAN
#define BIG_ENDIAN __BIG_ENDIAN
#define PDP_ENDIAN __PDP_ENDIAN
#define BYTE_ORDER __BYTE_ORDER

/* uint16_t */
#define htobe16(x) _byteswap_ushort((x))
#define htole16(x) (x)
#define be16toh(x) _byteswap_ushort((x))
#define le16toh(x) (x)

/* uint32_t */
#define htobe32(x) _byteswap_ulong((x))
#define htole32(x) (x)
#define be32toh(x) _byteswap_ulong((x))
#define le32toh(x) (x)

/* uint64_t */
#define htobe64(x) _byteswap_uint64((x))
#define htole64(x) (x)
#define be64toh(x) _byteswap_uint64((x))
#define le64toh(x) (x)

#endif /* _MSC_VER */

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* LINUX_ENDIAN_H */
