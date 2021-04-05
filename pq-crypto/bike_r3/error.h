/* Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0"
 *
 * Written by Nir Drucker, Shay Gueron and Dusan Kostic,
 * AWS Cryptographic Algorithms Group.
 */

#pragma once

#define SUCCESS 0
#define FAIL    (-1)

#define ret_t int __attribute__((warn_unused_result))
#define GUARD(x) \
  if((x) != SUCCESS) return FAIL

enum _bike_err
{
  E_DECODING_FAILURE         = 1,
  E_AES_CTR_PRF_INIT_FAIL    = 2,
  E_AES_OVER_USED            = 3,
  EXTERNAL_LIB_ERROR_OPENSSL = 4
};

typedef enum _bike_err _bike_err_t;

extern __thread _bike_err_t bike_errno;
#define BIKE_ERROR(x) \
  do {                \
    bike_errno = (x); \
    return FAIL;      \
  } while(0)
