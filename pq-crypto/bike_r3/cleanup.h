/* Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0"
 *
 * Written by Nir Drucker, Shay Gueron and Dusan Kostic,
 * AWS Cryptographic Algorithms Group.
 */

#pragma once

#include "utilities.h"

/* Runs _thecleanup function on _thealloc once _thealloc went out of scope */
#define DEFER_CLEANUP(_thealloc, _thecleanup) \
  __attribute__((cleanup(_thecleanup))) _thealloc

// len is bytes length of in
_INLINE_ void secure_clean(OUT uint8_t *p, IN const uint32_t len)
{
#if defined(_WIN32)
  SecureZeroMemory(p, len);
#else
  typedef void *(*memset_t)(void *, int, size_t);
  static volatile memset_t memset_func = bike_memset;
  memset_func(p, 0, len);
#endif
}

#define CLEANUP_FUNC(name, type)               \
  _INLINE_ void name##_cleanup(IN OUT type *o) \
  {                                            \
    secure_clean((uint8_t *)o, sizeof(*o));    \
  }

CLEANUP_FUNC(r, r_t)
CLEANUP_FUNC(m, m_t)
CLEANUP_FUNC(e, e_t)
CLEANUP_FUNC(sk, sk_t)
CLEANUP_FUNC(ss, ss_t)
CLEANUP_FUNC(ct, ct_t)
CLEANUP_FUNC(pad_r, pad_r_t)
CLEANUP_FUNC(pad_e, pad_e_t)
CLEANUP_FUNC(seed, seed_t)
CLEANUP_FUNC(syndrome, syndrome_t)
CLEANUP_FUNC(upc, upc_t)
CLEANUP_FUNC(func_k, func_k_t)
CLEANUP_FUNC(dbl_pad_r, dbl_pad_r_t)

// The functions below require special handling because we deal
// with arrays and not structures.

_INLINE_ void compressed_idx_d_ar_cleanup(IN OUT compressed_idx_d_ar_t *o)
{
  for(int i = 0; i < N0; i++) {
    secure_clean((uint8_t *)&(*o)[i], sizeof((*o)[0]));
  }
}

_INLINE_ void seeds_cleanup(IN OUT seeds_t *o)
{
  for(int i = 0; i < NUM_OF_SEEDS; i++) {
    seed_cleanup(&(o->seed[i]));
  }
}
