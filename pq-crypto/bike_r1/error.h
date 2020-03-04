/* Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0"
 *
 * Written by Nir Drucker and Shay Gueron
 * AWS Cryptographic Algorithms Group.
 * (ndrucker@amazon.com, gueron@amazon.com)
 */

#pragma once

#include "defs.h"

#define SUCCESS 0
#define FAIL    (-1)

#define ret_t int

enum _bike_err
{
  E_ERROR_WEIGHT_IS_NOT_T    = 1,
  E_DECODING_FAILURE         = 2,
  E_AES_CTR_PRF_INIT_FAIL    = 3,
  E_AES_OVER_USED            = 4,
  EXTERNAL_LIB_ERROR_OPENSSL = 5,
  E_FAIL_TO_GET_SEED         = 6
};

typedef enum _bike_err _bike_err_t;

extern __thread _bike_err_t bike_errno;
#define BIKE_ERROR(x) \
  do                  \
  {                   \
    bike_errno = (x); \
    return FAIL;      \
  } while(0)
