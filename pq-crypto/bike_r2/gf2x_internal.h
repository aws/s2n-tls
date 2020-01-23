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

#pragma once

#include "types.h"

EXTERNC void
karatzuba_add1(OUT uint64_t *res,
               IN const uint64_t *a,
               IN const uint64_t *b,
               IN const uint64_t  n_half,
               IN uint64_t *alah);

EXTERNC void
karatzuba_add2(OUT uint64_t *res1,
               OUT uint64_t *res2,
               IN const uint64_t *res,
               IN const uint64_t *tmp,
               IN const uint64_t  n_half);

EXTERNC void
red(uint64_t *res);

void
gf2x_mul_1x1(OUT uint64_t *res, IN const uint64_t a, IN const uint64_t b);
