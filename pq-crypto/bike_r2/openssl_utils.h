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
#  include <openssl/bn.h>
#  ifndef OPENSSL_NO_EC2M
#    define USE_OPENSSL_GF2M 1
#  endif
#endif

#ifdef USE_OPENSSL_GF2M

ret_t
ossl_add(OUT uint8_t      res_bin[R_SIZE],
         IN const uint8_t a_bin[R_SIZE],
         IN const uint8_t b_bin[R_SIZE]);

// Perform cyclic product by using OpenSSL
ret_t
cyclic_product(OUT uint8_t      res_bin[R_SIZE],
               IN const uint8_t a_bin[R_SIZE],
               IN const uint8_t b_bin[R_SIZE]);

#endif
