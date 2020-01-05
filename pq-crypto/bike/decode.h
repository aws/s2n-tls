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

void
split_e(OUT split_e_t *split_e_, IN const e_t *e);

ret_t
compute_syndrome(OUT syndrome_t *syndrome, IN const ct_t *ct, IN const sk_t *sk);

// e should be zeroed before calling the decoder.
ret_t
decode(OUT e_t *e,
       IN const syndrome_t *s,
       IN const ct_t *ct,
       IN const sk_t *   sk,
       IN const uint32_t u);
