/* Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0"
 *
 * Written by Nir Drucker, Shay Gueron and Dusan Kostic,
 * AWS Cryptographic Algorithms Group.
 */

#pragma once

#include <stddef.h>
#include <stdint.h>

#include "bike_defs.h"
#include "error.h"

typedef struct uint128_s {
  union {
    uint8_t  bytes[16]; // NOLINT
    uint32_t dw[4];     // NOLINT
    uint64_t qw[2];     // NOLINT
  } u;
} uint128_t;

// Make sure no compiler optimizations.
#pragma pack(push, 1)

typedef struct seed_s {
  uint8_t raw[SEED_BYTES];
} seed_t;

typedef struct seeds_s {
  seed_t seed[NUM_OF_SEEDS];
} seeds_t;

typedef struct r_s {
  uint8_t raw[R_BYTES];
} r_t;

typedef struct m_s {
  uint8_t raw[M_BYTES];
} m_t;

typedef struct e_s {
  r_t val[N0];
} e_t;

#define E0_RAW(e) ((e)->val[0].raw)
#define E1_RAW(e) ((e)->val[1].raw)

typedef struct ct_s {
  r_t c0;
  m_t c1;
} ct_t;

typedef r_t pk_t;

typedef struct ss_st {
  uint8_t raw[SS_BYTES];
} ss_t;

typedef uint32_t idx_t;

typedef struct compressed_idx_d_s {
  idx_t val[D];
} compressed_idx_d_t;

typedef compressed_idx_d_t compressed_idx_d_ar_t[N0];

// The secret key holds both representations, to avoid
// the compression in Decaps.
typedef struct sk_s {
  compressed_idx_d_ar_t wlist;
  r_t                   bin[N0];
  pk_t                  pk;
  m_t                   sigma;
} sk_t;

typedef ALIGN(sizeof(idx_t)) sk_t aligned_sk_t;

// Pad r to the next Block
typedef struct pad_r_s {
  r_t     val;
  uint8_t pad[R_PADDED_BYTES - sizeof(r_t)];
} ALIGN(ALIGN_BYTES) pad_r_t;

// Double padded r, required for multiplication and squaring
typedef struct dbl_pad_r_s {
  uint8_t raw[2 * R_PADDED_BYTES];
} ALIGN(ALIGN_BYTES) dbl_pad_r_t;

typedef struct pad_e_s {
  pad_r_t val[N0];
} ALIGN(ALIGN_BYTES) pad_e_t;

#define PE0_RAW(e) ((e)->val[0].val.raw)
#define PE1_RAW(e) ((e)->val[1].val.raw)

typedef struct func_k_s {
  m_t m;
  r_t c0;
  m_t c1;
} func_k_t;

// For a faster rotate we triplicate the syndrome (into 3 copies)
typedef struct syndrome_s {
  uint64_t qw[3 * R_QWORDS];
} ALIGN(ALIGN_BYTES) syndrome_t;

typedef struct upc_slice_s {
  union {
    pad_r_t  r;
    uint64_t qw[sizeof(pad_r_t) / sizeof(uint64_t)];
  } ALIGN(ALIGN_BYTES) u;
} ALIGN(ALIGN_BYTES) upc_slice_t;

typedef struct upc_s {
  upc_slice_t slice[SLICES];
} upc_t;

#pragma pack(pop)
