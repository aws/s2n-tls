/* Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0"
 *
 * Written by Nir Drucker and Shay Gueron,
 * AWS Cryptographic Algorithms Group.
 * (ndrucker@amazon.com, gueron@amazon.com)
 */

#pragma once

#include "types.h"

#ifdef USE_OPENSSL
#  include "openssl_utils.h"
#endif

#ifdef USE_OPENSSL_GF2M
// res = a*b mod (x^r - 1)
// Note: the caller must allocate twice the size of res.
_INLINE_ ret_t
gf2x_mod_mul(OUT uint64_t *res, IN const uint64_t *a, IN const uint64_t *b)
{
  return cyclic_product((uint8_t *)res, (const uint8_t *)a, (const uint8_t *)b);
}

// A wrapper for other gf2x_add implementations.
_INLINE_ ret_t
gf2x_add(OUT uint8_t *res,
         IN const uint8_t *a,
         IN const uint8_t *b,
         IN const uint64_t size)
{
  BIKE_UNUSED(size);
  return ossl_add((uint8_t *)res, a, b);
}
#else // USE_OPENSSL_GF2M

_INLINE_ ret_t
gf2x_add(OUT uint8_t *res,
         IN const uint8_t *a,
         IN const uint8_t *b,
         IN const uint64_t bytelen)
{
  for(uint64_t i = 0; i < bytelen; i++)
  {
    res[i] = a[i] ^ b[i];
  }
  return SUCCESS;
}

// res = a*b mod (x^r - 1)
// the caller must allocate twice the size of res!
ret_t
gf2x_mod_mul(OUT uint64_t *res, IN const uint64_t *a, IN const uint64_t *b);
#endif
