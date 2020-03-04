/* Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0"
 *
 * Written by Nir Drucker and Shay Gueron,
 * AWS Cryptographic Algorithms Group.
 * (ndrucker@amazon.com, gueron@amazon.com)
 */

#pragma once

#include "types.h"

EXTERNC void
karatzuba_add1(OUT uint64_t *res,
               IN const uint64_t *a,
               IN const uint64_t *b,
               IN uint64_t        n_half,
               IN uint64_t *alah);

EXTERNC void
karatzuba_add2(OUT uint64_t *res1,
               OUT uint64_t *res2,
               IN const uint64_t *res,
               IN const uint64_t *tmp,
               IN uint64_t        n_half);

EXTERNC void
red(uint64_t *res);

void

gf2x_mul_1x1(OUT uint64_t *res, IN uint64_t a, IN uint64_t b);
