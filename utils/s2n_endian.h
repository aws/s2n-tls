/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"). You may not use
 * this file except in compliance with the License. A copy of the License is
 * located at
 *
 *     http://aws.amazon.com/apache2.0/
 *
 * or in the "license" file accompanying this file. This file is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 * implied. See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifdef _MSC_VER

#include <stdlib.h>
#define bswap_16(x) _byteswap_ushort(x)
#define bswap_32(x) _byteswap_ulong(x)
#define bswap_64(x) _byteswap_uint64(x)

#elif defined(__APPLE__)

#include <libkern/OSByteOrder.h>
#define bswap_16(x) OSSwapInt16(x)
#define bswap_32(x) OSSwapInt32(x)
#define bswap_64(x) OSSwapInt64(x)

#elif defined(__sun) || defined(sun)

#include <sys/byteorder.h>
#define bswap_16(x) BSWAP_16(x)
#define bswap_32(x) BSWAP_32(x)
#define bswap_64(x) BSWAP_64(x)

#elif defined(__FreeBSD__)

#include <sys/endian.h>
#define bswap_16(x) bswap16(x)
#define bswap_32(x) bswap32(x)
#define bswap_64(x) bswap64(x)

#elif defined(__OpenBSD__)

#include <sys/types.h>
#define bswap_16(x) swap16(x)
#define bswap_32(x) swap32(x)
#define bswap_64(x) swap64(x)

#elif defined(__NetBSD__)

#include <sys/types.h>
#include <machine/bswap.h>
#if defined(__BSWAP_RENAME) && !defined(__bswap_32)
#define bswap_16(x) bswap16(x)
#define bswap_32(x) bswap32(x)
#define bswap_64(x) bswap64(x)
#endif

#else

#include <byteswap.h>

#endif

#if __BYTE_ORDER == __LITTLE_ENDIAN
#    define htobe16(x) bswap_16(x)
#    define htole16(x) (x)
#    define be16toh(x) bswap_16(x)
#    define le16toh(x) (x)

#    define htobe32(x) bswap_32(x)
#    define htole32(x) (x)
#    define be32toh(x) bswap_32(x)
#    define le32toh(x) (x)

#    define htobe64(x) bswap_64(x)
#    define htole64(x) (x)
#    define be64toh(x) bswap_64(x)
#    define le64toh(x) (x)
#else
#    define htobe16(x) (x)
#    define htole16(x) bswap_16(x)
#    define be16toh(x) (x)
#    define le16toh(x) bswap_16(x)

#    define htobe32(x) (x)
#    define htole32(x) bswap_32(x)
#    define be32toh(x) (x)
#    define le32toh(x) bswap_32(x)

#    define htobe64(x) (x)
#    define htole64(x) bswap_64(x)
#    define be64toh(x) (x)
#    define le64toh(x) bswap_64(x)
#endif
