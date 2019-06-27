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

#include "openssl_utils.h"

//res = a*b mod (x^r - 1)
//the caller must allocate twice the size of res!
_INLINE_ ret_t gf2x_mod_mul(OUT uint64_t *res,
                            IN const uint64_t *a, 
                            IN const uint64_t *b)
{
    return cyclic_product((uint8_t*)res, (const uint8_t*)a, (const uint8_t*)b);
}

//A wrapper for other gf2x_add implementations.
_INLINE_ ret_t gf2x_add(OUT uint8_t *res, 
                        IN const uint8_t *a, 
                        IN const uint8_t *b, 
                        IN const uint64_t size)
{
    BIKE_UNUSED(size);
    return ossl_add((uint8_t*)res, a, b);
}
