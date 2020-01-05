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

ret_t
ossl_add(OUT uint8_t      res_bin[R_SIZE],
         IN const uint8_t a_bin[R_SIZE],
         IN const uint8_t b_bin[R_SIZE]);

// Perform cyclic product by using OpenSSL
ret_t
cyclic_product(OUT uint8_t      res_bin[R_SIZE],
               IN const uint8_t a_bin[R_SIZE],
               IN const uint8_t b_bin[R_SIZE]);
