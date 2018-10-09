/***************************************************************************
* Additional implementation of "BIKE: Bit Flipping Key Encapsulation". 
* Copyright 2017 Amazon.com, Inc. or its affiliates. All Rights Reserved.
*
* Written by Nir Drucker and Shay Gueron
* AWS Cryptographic Algorithms Group
* (ndrucker@amazon.com, gueron@amazon.com)
*
* The license is detailed in the file LICENSE.txt, and applies to this file.
* ***************************************************************************/

#ifndef _GF2MUL_H_
#define _GF2MUL_H_

#include "types.h"

#ifdef USE_OPENSSL
  #include "openssl_utils.h"
#else
  #include "ntl.h"
#endif

#ifdef USE_OPENSSL
//res = a*b mod (x^r - 1)
//the caller must allocate twice the size of res!
_INLINE_ status_t gf2x_mod_mul(OUT uint64_t *res,
                               IN const uint64_t *a, 
                               IN const uint64_t *b)
{
    return cyclic_product((uint8_t*)res, (const uint8_t*)a, (const uint8_t*)b);
}

//A wrapper for other gf2x_add implementations.
_INLINE_ status_t gf2x_add(OUT uint8_t *res, 
                           IN const uint8_t *a, 
                           IN const uint8_t *b, 
                           IN const uint64_t size)
{
    BIKE_UNUSED(size);
    return ossl_add((uint8_t*)res, a, b);
}

#else

//Found in the assembly files.
//size is the number of bytes in a/b/res (all equal!)
extern void gf2x_add_avx2(OUT const uint8_t *res, 
                          IN const uint8_t *a, 
                          IN const uint8_t *b, 
                          IN const uint64_t size);

//A wrapper for other gf2x_add implementations.
_INLINE_ status_t gf2x_add(const uint8_t *res, const uint8_t *a, const uint8_t *b, const uint64_t size)
{
    gf2x_add_avx2(res, a, b, size);
    return SUCCESS;
}

//res = a*b mod (x^r - 1)
//the caller must allocate twice the size of res!
status_t gf2x_mod_mul(OUT uint64_t *res, 
                      IN const uint64_t *a, 
                      IN const uint64_t *b);
#endif

#endif //_GF2MUL_H_
