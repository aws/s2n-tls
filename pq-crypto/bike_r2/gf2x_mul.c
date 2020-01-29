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

#include "cleanup.h"
#include "gf2x.h"
#include "gf2x_internal.h"
#include <stdlib.h>
#include <string.h>
#include "cleanup.h"

#ifndef USE_OPENSSL_GF2M

/* All the temporary data (which might hold secrets)
 * is stored on a secure buffer, so that it can be easily cleaned up later.
 * The secure buffer required is: 3n/2 (alah|blbh|tmp) in a recursive way.
 * 3n/2 + 3n/4 + 3n/8 = 3(n/2 + n/4 + n/8) < 3n
 */
#  define SECURE_BUFFER_SIZE (3 * R_PADDED_SIZE)

/* This functions assumes that n is even. */
_INLINE_ void
karatzuba(OUT uint64_t *res,
          IN const uint64_t *a,
          IN const uint64_t *b,
          IN const uint64_t  n,
          uint64_t *         secure_buf)
{
  if(1 == n)
  {
    gf2x_mul_1x1(res, a[0], b[0]);
    return;
  }

  const uint64_t half_n = n >> 1;

  /* Define pointers for the middle of each parameter
     sepearting a=a_low and a_high (same for ba nd res) */
  const uint64_t *a_high = a + half_n;
  const uint64_t *b_high = b + half_n;

  /* Divide res into 4 parts res3|res2|res1|res in size n/2 */
  uint64_t *res1 = res + half_n;
  uint64_t *res2 = res1 + half_n;

  /* All three parameters below are allocated on the secure buffer
     All of them are in size half n */
  uint64_t *alah = secure_buf;
  uint64_t *blbh = alah + half_n;
  uint64_t *tmp  = blbh + half_n;

  /* Place the secure buffer ptr in the first free location,
   * so the recursive function can use it. */
  secure_buf = tmp + half_n;

  /* Calculate Z0 and store the result in res(low) */
  karatzuba(res, a, b, half_n, secure_buf);

  /* Calculate Z2 and store the result in res(high) */
  karatzuba(res2, a_high, b_high, half_n, secure_buf);

  /* Accomulate the results. */
  karatzuba_add1(res, a, b, half_n, alah);

  /* (a_low + a_high)(b_low + b_high) --> res1 */
  karatzuba(res1, alah, blbh, half_n, secure_buf);

  karatzuba_add2(res1, res2, res, tmp, half_n);
}

ret_t
gf2x_mod_mul(OUT uint64_t *res, IN const uint64_t *a, IN const uint64_t *b)
{
  bike_static_assert((R_PADDED_QW % 2 == 0), karatzuba_n_is_odd);

  /*
   * Casting from uint8_t array to uint64_t * on clang-3 produces:
   *
   * cast from 'uint8_t *' (aka 'unsigned char *') to 'uint64_t *' (aka 'unsigned long long *')
   * increases required alignment from 1 to 4 [-Werror,-Wcast-align]
   *
   * in this case prove it's fine, and then override the compiler on it.
   */
  ALIGN(sizeof(uint64_t)) uint8_t secure_buffer[SECURE_BUFFER_SIZE];
  /* make sure we have the correct size allocation. */
  bike_static_assert(sizeof(secure_buffer) % sizeof(uint64_t) == 0, secure_buffer_not_eligable_for_uint64_t);

  uint64_t *secure_buffer_ptr = (uint64_t *)(void *)secure_buffer;
  karatzuba(res, a, b, R_PADDED_QW, secure_buffer_ptr);

  /* This function implicitly assumes that the size of res is 2*R_PADDED_QW. */
  red(res);

  secure_clean(secure_buffer, sizeof(secure_buffer));

  return SUCCESS;
}

#endif /* USE_OPENSSL_GF2M */
