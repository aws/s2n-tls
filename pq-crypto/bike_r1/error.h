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

#define SUCCESS 0
#define FAIL    (-1)

typedef int ret_t;

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
