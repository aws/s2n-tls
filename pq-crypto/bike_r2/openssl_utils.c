/*
 * Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

#include "openssl_utils.h"
#include "utilities.h"
#include <assert.h>
#include <openssl/bn.h>
#include <string.h>

#ifdef USE_OPENSSL_GF2M

#  define MAX_OPENSSL_INV_TRIALS 1000

_INLINE_ void
BN_CTX_cleanup(BN_CTX *ctx)
{
  if(ctx)
  {
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
  }
}

DEFINE_POINTER_CLEANUP_FUNC(BN_CTX *, BN_CTX_cleanup);

// Loading (big) numbers into OpenSSL should use Big Endian representation.
// Therefore, the bytes ordering of the number should be reversed.
_INLINE_ void
reverse_endian(OUT uint8_t *res, IN const uint8_t *in, IN const uint32_t n)
{
  uint32_t i;
  uint64_t tmp;

  for(i = 0; i < (n / 2); i++)
  {
    tmp            = in[i];
    res[i]         = in[n - 1 - i];
    res[n - 1 - i] = tmp;
  }

  // If the number of blocks is odd, swap also the middle block.
  if(n % 2)
  {
    res[i] = in[i];
  }
}

_INLINE_ ret_t
ossl_bn2bin(OUT uint8_t *out, IN const BIGNUM *in, IN const uint32_t size)
{
  assert(size <= N_SIZE);
  uint8_t be_tmp[N_SIZE] = {0};

  memset(out, 0, size);

  if(BN_bn2bin(in, be_tmp) == -1)
  {
    BIKE_ERROR(EXTERNAL_LIB_ERROR_OPENSSL);
  }
  reverse_endian(out, be_tmp, BN_num_bytes(in));

  return SUCCESS;
}

_INLINE_ ret_t
ossl_bin2bn(IN BIGNUM *out, OUT const uint8_t *in, IN const uint32_t size)
{
  assert(size <= N_SIZE);
  uint8_t be_tmp[N_SIZE] = {0};

  reverse_endian(be_tmp, in, size);

  if(BN_bin2bn(be_tmp, size, out) == 0)
  {
    BIKE_ERROR(EXTERNAL_LIB_ERROR_OPENSSL);
  }

  return SUCCESS;
}

ret_t
ossl_add(OUT uint8_t      res_bin[R_SIZE],
         IN const uint8_t a_bin[R_SIZE],
         IN const uint8_t b_bin[R_SIZE])
{
  DEFER_CLEANUP(BN_CTX *bn_ctx = BN_CTX_new(), BN_CTX_cleanup_pointer);
  BIGNUM *r = NULL;
  BIGNUM *a = NULL;
  BIGNUM *b = NULL;

  if(NULL == bn_ctx)
  {
    BIKE_ERROR(EXTERNAL_LIB_ERROR_OPENSSL);
  }

  BN_CTX_start(bn_ctx);

  r = BN_CTX_get(bn_ctx);
  a = BN_CTX_get(bn_ctx);
  b = BN_CTX_get(bn_ctx);

  if((NULL == r) || (NULL == a) || (NULL == b))
  {
    BIKE_ERROR(EXTERNAL_LIB_ERROR_OPENSSL);
  }

  GUARD(ossl_bin2bn(a, a_bin, R_SIZE));
  GUARD(ossl_bin2bn(b, b_bin, R_SIZE));

  if(BN_GF2m_add(r, a, b) == 0)
  {
    BIKE_ERROR(EXTERNAL_LIB_ERROR_OPENSSL);
  }

  GUARD(ossl_bn2bin(res_bin, r, R_SIZE));

  return SUCCESS;
}

// Perform a cyclic product by using OpenSSL.
_INLINE_ ret_t
ossl_cyclic_product(OUT BIGNUM *r,
                    IN const BIGNUM *a,
                    IN const BIGNUM *b,
                    BN_CTX *         bn_ctx)
{
  BIGNUM *m = BN_CTX_get(bn_ctx);
  if(NULL == m)
  {
    BIKE_ERROR(EXTERNAL_LIB_ERROR_OPENSSL);
  }

  // m = x^PARAM_R - 1
  if((BN_set_bit(m, R_BITS) == 0) || (BN_set_bit(m, 0) == 0))
  {
    BIKE_ERROR(EXTERNAL_LIB_ERROR_OPENSSL);
  }

  // r = a*b mod m
  if(BN_GF2m_mod_mul(r, a, b, m, bn_ctx) == 0)
  {
    BIKE_ERROR(EXTERNAL_LIB_ERROR_OPENSSL);
  }

  return SUCCESS;
}

// Perform a cyclic product by using OpenSSL.
ret_t
cyclic_product(OUT uint8_t      res_bin[R_SIZE],
               IN const uint8_t a_bin[R_SIZE],
               IN const uint8_t b_bin[R_SIZE])
{
  DEFER_CLEANUP(BN_CTX *bn_ctx = BN_CTX_new(), BN_CTX_cleanup_pointer);
  BIGNUM *r = NULL;
  BIGNUM *a = NULL;
  BIGNUM *b = NULL;

  if(NULL == bn_ctx)
  {
    BIKE_ERROR(EXTERNAL_LIB_ERROR_OPENSSL);
  }

  BN_CTX_start(bn_ctx);

  r = BN_CTX_get(bn_ctx);
  a = BN_CTX_get(bn_ctx);
  b = BN_CTX_get(bn_ctx);

  if((NULL == r) || (NULL == a) || (NULL == b))
  {
    BIKE_ERROR(EXTERNAL_LIB_ERROR_OPENSSL);
  }

  GUARD(ossl_bin2bn(a, a_bin, R_SIZE));
  GUARD(ossl_bin2bn(b, b_bin, R_SIZE));
  GUARD(ossl_cyclic_product(r, a, b, bn_ctx));
  GUARD(ossl_bn2bin(res_bin, r, R_SIZE));

  return SUCCESS;
}

#endif // USE_OPENSSL_GF2M
