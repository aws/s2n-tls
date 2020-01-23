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

#include "bike_defs.h"
#include "error.h"
#include <stdint.h>

typedef struct uint128_s
{
  union {
    uint8_t  bytes[16];
    uint32_t dw[4];
    uint64_t qw[2];
  } u;
} uint128_t;

// Make sure no compiler optimizations.
#pragma pack(push, 1)

typedef struct seed_s
{
  uint8_t raw[32];
} seed_t;

typedef struct seeds_s
{
  seed_t seed[NUM_OF_SEEDS];
} seeds_t;

typedef struct r_s
{
  uint8_t raw[R_SIZE];
} r_t;

typedef struct e_s
{
  uint8_t raw[N_SIZE];
} e_t;

typedef struct generic_param_n_s
{
  r_t val[N0];
} generic_param_n_t;

typedef generic_param_n_t ct_t;
typedef generic_param_n_t pk_t;
typedef generic_param_n_t split_e_t;

typedef uint32_t idx_t;

typedef struct compressed_idx_dv_s
{
  idx_t val[DV];
} compressed_idx_dv_t;

typedef compressed_idx_dv_t compressed_idx_dv_ar_t[N0];

typedef struct compressed_idx_t_t
{
  idx_t val[T1];
} compressed_idx_t_t;

// The secret key holds both representation for avoiding
// the compression in the decaps stage
typedef struct sk_s
{
  r_t                    bin[N0];
  compressed_idx_dv_ar_t wlist;
#ifndef INDCPA
  r_t sigma0;
  r_t sigma1;
#endif
} sk_t;

// Pad e to the next Block
typedef ALIGN(8) struct padded_e_s
{
  e_t     val;
  uint8_t pad[N_PADDED_SIZE - N_SIZE];
} padded_e_t;

// Pad r to the next Block
typedef ALIGN(8) struct padded_r_s
{
  r_t     val;
  uint8_t pad[R_PADDED_SIZE - R_SIZE];
} padded_r_t;

typedef padded_r_t       padded_param_n_t[N0];
typedef padded_param_n_t pad_sk_t;
typedef padded_param_n_t pad_pk_t;
typedef padded_param_n_t pad_ct_t;

// Need to allocate twice the room for the results
typedef ALIGN(8) struct dbl_padded_r_s
{
  r_t     val;
  uint8_t pad[(2 * R_PADDED_SIZE) - R_SIZE];
} dbl_padded_r_t;

typedef dbl_padded_r_t       dbl_padded_param_n_t[N0];
typedef dbl_padded_param_n_t dbl_pad_pk_t;
typedef dbl_padded_param_n_t dbl_pad_ct_t;
typedef dbl_padded_param_n_t dbl_pad_syndrome_t;

typedef struct ss_s
{
  uint8_t raw[ELL_K_SIZE];
} ss_t;

// For optimization purposes
//  1- For a faster rotate we duplicate the syndrome (dup1/2)
//  2- We extend it to fit the boundary of DDQW
typedef ALIGN(64) struct syndrome_s
{
  uint64_t qw[3 * R_QW];
} syndrome_t;

typedef struct upc_slice_s
{
  union {
    padded_r_t r;
    uint64_t   qw[sizeof(padded_r_t) / 8];
  } u;
} upc_slice_t;

typedef struct upc_s
{
  upc_slice_t slice[SLICES];
} upc_t;

#pragma pack(pop)
