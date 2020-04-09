/* Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0"
 *
 * Written by Nir Drucker and Shay Gueron
 * AWS Cryptographic Algorithms Group.
 * (ndrucker@amazon.com, gueron@amazon.com)
 */

#pragma once

#include "types.h"

ret_t
compute_syndrome(OUT syndrome_t *syndrome, IN const ct_t *ct, IN const sk_t *sk);

// e should be zeroed before calling the decoder.
ret_t
decode(OUT split_e_t *e,
       IN const syndrome_t *s,
       IN const ct_t *ct,
       IN const sk_t *sk);

// Rotate right the first R_BITS of a syndrome.
// Assumption: the syndrome contains three R_BITS duplications.
// The output syndrome contains only one R_BITS rotation, the other
// (2 * R_BITS) bits are undefined.
void
rotate_right(OUT syndrome_t *out, IN const syndrome_t *in, IN uint32_t bitscount);
