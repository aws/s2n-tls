/***************************************************************************
* Additional implementation of "BIKE: Bit Flipping Key Encapsulation". 
* Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
*
* Written by Nir Drucker and Shay Gueron
* AWS Cryptographic Algorithms Group
* (ndrucker@amazon.com, gueron@amazon.com)
*
* The license is detailed in the file LICENSE.md, and applies to this file.
* ***************************************************************************/

#pragma once

#include "types.h"
#include "utilities.h"
#include <openssl/sha.h>

#define SHA384_HASH_SIZE    48ULL
#define SHA384_HASH_QWORDS  (SHA384_HASH_SIZE/8)

#define SHA512_HASH_SIZE    64ULL
#define SHA512_HASH_QWORDS  (SHA512_HASH_SIZE/8)

typedef struct sha384_hash_s
{
    union
    {
         uint8_t  raw[SHA384_HASH_SIZE];
         uint64_t qw[SHA384_HASH_QWORDS];
    } u;
} sha384_hash_t;
bike_static_assert(sizeof(sha384_hash_t) == SHA384_HASH_SIZE, sha384_hash_size);

typedef struct sha512_hash_s
{
    union
    {
         uint8_t  raw[SHA512_HASH_SIZE];
         uint64_t qw[SHA512_HASH_QWORDS];
    } u;
} sha512_hash_t;
bike_static_assert(sizeof(sha512_hash_t) == SHA512_HASH_SIZE, sha512_hash_size);

typedef struct {
    const uint8_t *ptr;
    uint32_t blocks;
} hash_desc;

#define NUM_OF_BLOCKS_IN_MB 4ULL

#define SLICE_REM           111ULL
#define MAX_MB_SLICES       8ULL
#define HASH_BLOCK_SIZE     128ULL

typedef sha384_hash_t sha_hash_t;
typedef uint64_t block_t;

_INLINE_ int sha(OUT sha_hash_t *hash_out,
                 IN const uint32_t byte_len,
                 IN const uint8_t *msg)
{
    SHA384(msg, byte_len, hash_out->u.raw);
    return 1;
}

_INLINE_ void sha_mb(OUT sha_hash_t *hash_out,
                     IN const uint8_t *msg,
                     IN const uint32_t byte_len,
                     IN const uint32_t num) 
{
    const uint32_t ls = (byte_len / NUM_OF_BLOCKS_IN_MB);

    // Hash each block (X[i])
    for (uint32_t i = 0; i < num; i++) {
        SHA384(&msg[i * ls], ls, hash_out[i].u.raw);
    }
}
