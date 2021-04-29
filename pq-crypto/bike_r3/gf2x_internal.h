/* Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0"
 *
 * Written by Nir Drucker, Shay Gueron and Dusan Kostic,
 * AWS Cryptographic Algorithms Group.
 */

#pragma once

// For size_t
#include <stdlib.h>

#include "types.h"

// The size in quadwords of the operands in the gf2x_mul_base function
// for different implementations.
#if defined(PCLMUL)
#  define GF2X_BASE_QWORDS (8)
#elif defined(VPCLMUL)
#  define GF2X_BASE_QWORDS (16)
#else
#  define GF2X_BASE_QWORDS (1)
#endif

// GF2X multiplication of a and b of size GF2X_BASE_QWORDS, c = a * b
void gf2x_mul_base(OUT uint64_t *c, IN const uint64_t *a, IN const uint64_t *b);

// c = a^2
void gf2x_sqr(OUT dbl_pad_r_t *c, IN const pad_r_t *a);

// a = a^2 mod (x^r - 1)
void gf2x_mod_sqr_in_place(IN OUT pad_r_t *a, OUT dbl_pad_r_t *secure_buffer);

// The k-squaring function computes c = a^(2^k) % (x^r - 1),
// It is required by inversion, where l_param is derived from k.
void k_squaring(OUT pad_r_t *c, IN const pad_r_t *a, IN size_t l_param);
