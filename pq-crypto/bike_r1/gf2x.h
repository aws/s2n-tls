/*
 * Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * A copy of the License is located at
 *
 * http://aws.amazon.com/apache2.0
 *
 * or in the "license" file accompanying this file. This file is distributed
 * on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 * The license is detailed in the file LICENSE.md, and applies to this file.
 *
 * Written by Nir Drucker and Shay Gueron
 * AWS Cryptographic Algorithms Group.
 * (ndrucker@amazon.com, gueron@amazon.com)
 */

#pragma once

#include "types.h"

#include "openssl_utils.h"

// res = a*b mod (x^r - 1)
// the caller must allocate twice the size of res!
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
