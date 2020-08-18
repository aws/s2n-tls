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

#if __BYTE_ORDER == __LITTLE_ENDIAN
#    define __LONG_LONG_PAIR(HI, LO) LO, HI
#elif __BYTE_ORDER == __BIG_ENDIAN
#    define __LONG_LONG_PAIR(HI, LO) HI, LO
#endif

#if __BYTE_ORDER == __LITTLE_ENDIAN
#    define htobe16(x) __builtin_bswap16(x)
#    define htole16(x) (x)
#    define be16toh(x) __builtin_bswap16(x)
#    define le16toh(x) (x)

#    define htobe32(x) __builtin_bswap32(x)
#    define htole32(x) (x)
#    define be32toh(x) __builtin_bswap32(x)
#    define le32toh(x) (x)

#    define htobe64(x) __builtin_bswap64(x)
#    define htole64(x) (x)
#    define be64toh(x) __builtin_bswap64(x)
#    define le64toh(x) (x)
#else
#    define htobe16(x) (x)
#    define htole16(x) __builtin_bswap16(x)
#    define be16toh(x) (x)
#    define le16toh(x) __builtin_bswap16(x)

#    define htobe32(x) (x)
#    define htole32(x) __builtin_bswap32(x)
#    define be32toh(x) (x)
#    define le32toh(x) __builtin_bswap32(x)

#    define htobe64(x) (x)
#    define htole64(x) __builtin_bswap64(x)
#    define be64toh(x) (x)
#    define le64toh(x) __builtin_bswap64(x)
#endif
