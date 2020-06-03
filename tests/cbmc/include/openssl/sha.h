/*
 * Changes to OpenSSL version 1.1.1.
 * Copyright Amazon.com, Inc. All Rights Reserved.
 * Copyright 1995-2017 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * A copy of the License is located at
 *
 *  http://aws.amazon.com/apache2.0
 *
 * or in the "license" file accompanying this file. This file is distributed
 * on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */

#ifndef HEADER_SHA_H
#define HEADER_SHA_H

/*
 * !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
 * ! SHA_LONG has to be at least 32 bits wide. If it's wider, then !
 * ! SHA_LONG_LOG2 has to be defined along.                        !
 * !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
 */

#if defined(__LP32__)
#    define SHA_LONG unsigned long
#elif defined(OPENSSL_SYS_CRAY) || defined(__ILP64__)
#    define SHA_LONG unsigned long
#    define SHA_LONG_LOG2 3
#else
#    define SHA_LONG unsigned int
#endif

#define SHA_LBLOCK 16
#define SHA_CBLOCK \
    (SHA_LBLOCK * 4) /* SHA treats input data as a
					 * contiguous array of 32 bit
					 * wide big-endian values. */
#define SHA_LAST_BLOCK (SHA_CBLOCK - 8)
#define SHA_DIGEST_LENGTH 20

typedef struct SHAstate_st {
    SHA_LONG     h0, h1, h2, h3, h4;
    SHA_LONG     Nl, Nh;
    SHA_LONG     data[ SHA_LBLOCK ];
    unsigned int num;
} SHA_CTX;

#define SHA256_CBLOCK \
    (SHA_LBLOCK * 4) /* SHA-256 treats input data as a
  					 * contiguous array of 32 bit
  					 * wide big-endian values. */
#define SHA224_DIGEST_LENGTH 28
#define SHA256_DIGEST_LENGTH 32

typedef struct SHA256state_st {
    SHA_LONG     h[ 8 ];
    SHA_LONG     Nl, Nh;
    SHA_LONG     data[ SHA_LBLOCK ];
    unsigned int num, md_len;
} SHA256_CTX;

#define SHA384_DIGEST_LENGTH 48
#define SHA512_DIGEST_LENGTH 64

#ifndef OPENSSL_NO_SHA512
/*
     * Unlike 32-bit digest algorithms, SHA-512 *relies* on SHA_LONG64
     * being exactly 64-bit wide. See Implementation Notes in sha512.c
     * for further details.
     */
#    define SHA512_CBLOCK \
        (SHA_LBLOCK * 8) /* SHA-512 treats input data as a
    					 * contiguous array of 64 bit
    					 * wide big-endian values. */
#    if (defined(_WIN32) || defined(_WIN64)) && !defined(__MINGW32__)
#        define SHA_LONG64 unsigned __int64
#        define U64(C) C##UI64
#    elif defined(__arch64__)
#        define SHA_LONG64 unsigned long
#        define U64(C) C##UL
#    else
#        define SHA_LONG64 unsigned long long
#        define U64(C) C##ULL
#    endif

typedef struct SHA512state_st {
    SHA_LONG64 h[ 8 ];
    SHA_LONG64 Nl, Nh;
    union {
        SHA_LONG64    d[ SHA_LBLOCK ];
        unsigned char p[ SHA512_CBLOCK ];
    } u;
    unsigned int num, md_len;
} SHA512_CTX;
#endif

#endif
