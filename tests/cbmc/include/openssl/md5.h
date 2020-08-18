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

#ifndef HEADER_MD5_H
#define HEADER_MD5_H

/*
 * !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
 * ! MD5_LONG has to be at least 32 bits wide. If it's wider, then !
 * ! MD5_LONG_LOG2 has to be defined along.			   !
 * !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
 */

#if defined(__LP32__)
#    define MD5_LONG unsigned long
#elif defined(OPENSSL_SYS_CRAY) || defined(__ILP64__)
#    define MD5_LONG unsigned long
#    define MD5_LONG_LOG2 3
/*
 * _CRAY note. I could declare short, but I have no idea what impact
 * does it have on performance on none-T3E machines. I could declare
 * int, but at least on C90 sizeof(int) can be chosen at compile time.
 * So I've chosen long...
 *					<appro@fy.chalmers.se>
 */
#else
#    define MD5_LONG unsigned int
#endif

#define MD5_CBLOCK 64
#define MD5_LBLOCK (MD5_CBLOCK / 4)
#define MD5_DIGEST_LENGTH 16

typedef struct MD5state_st {
    MD5_LONG     A, B, C, D;
    MD5_LONG     Nl, Nh;
    MD5_LONG     data[ MD5_LBLOCK ];
    unsigned int num;
} MD5_CTX;

#endif
