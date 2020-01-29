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

#include "bike_defs.h"
#include "error.h"
#include <stdint.h>

// C99 standard does not support unnamed union and structures.
// This makes the code ugly because we get ugly lines such as
// param.foo1.foo2.foo3.val = param.foo1.foo5.foo6.val
// To avoid this we always use the same structure
// struct { union { struct { some val } v; } u; } name.
// Subsequently, we can make the code more readable by using the three macros
// below. It will be shorter to use P() and V() instead of PTR/VAL, respectively.
// However then it will be harder to "grep" it.
#define PTR(x)  x->u.v
#define PTRV(x) (x->u.v.val)
#define VAL(x)  (x.u.v.val)

typedef struct uint128_s
{
  union {
    uint8_t  bytes[16];
    uint32_t dw[4];
    uint64_t qw[2];
  } u;
} uint128_t;

// Make sure no compiler optimizations
#pragma pack(push, 1)

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
  union {
    struct
    {
      r_t val[N0];
    } v;
    uint8_t raw[N_SIZE];
  } u;
} generic_param_n_t;

typedef generic_param_n_t pk_t;
typedef generic_param_n_t ct_t;
typedef generic_param_n_t split_e_t;

typedef struct idx_s
{
  uint32_t val;
  uint32_t used;
} idx_t;

typedef struct compressed_idx_dv_s
{
  idx_t val[FAKE_DV];
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
  union {
    struct
    {
      r_t                 bin[N0];
      compressed_idx_dv_t wlist[N0];
    } v;
    uint8_t raw[N0 * (sizeof(r_t) + sizeof(compressed_idx_dv_t))];
  } u;
} sk_t;

// Pad e to the next Block
typedef struct padded_e_s
{
  union {
    struct
    {
      e_t     val;
      uint8_t pad[N_PADDED_SIZE - N_SIZE];
    } v;
    uint64_t qw[N_PADDED_QW];
    uint8_t  raw[N_PADDED_SIZE];
  } u;
} padded_e_t;

// Pad r to the next Block
typedef struct padded_r_s
{
  union {
    struct
    {
      r_t     val;
      uint8_t pad[R_PADDED_SIZE - R_SIZE];
    } v;
    uint64_t qw[R_PADDED_QW];
    uint8_t  raw[R_PADDED_SIZE];
  } u;
} padded_r_t;

typedef padded_r_t       padded_param_n_t[N0];
typedef padded_param_n_t pad_sk_t;
typedef padded_param_n_t pad_pk_t;
typedef padded_param_n_t pad_ct_t;

// Need to allocate twice the room for the results
typedef struct dbl_padded_r_s
{
  union {
    struct
    {
      r_t     val;
      uint8_t pad[(2 * R_PADDED_SIZE) - R_SIZE];
    } v;
    uint64_t qw[2 * R_PADDED_QW];
    uint8_t  raw[2 * R_PADDED_SIZE];
  } u;
} dbl_padded_r_t;

typedef dbl_padded_r_t       dbl_padded_param_n_t[N0];
typedef dbl_padded_param_n_t dbl_pad_pk_t;
typedef dbl_padded_param_n_t dbl_pad_ct_t;
typedef dbl_padded_param_n_t dbl_pad_syndrome_t;

typedef struct ss_s
{
  uint8_t raw[ELL_K_SIZE];
} ss_t;

// R in redundant representation
typedef struct red_r_s
{
  uint8_t raw[R_BITS];
} red_r_t;

// For optimization purposes
//  1- For a faster rotate we duplicate the syndrome (dup1/2)
//  2- We extend it to fit the boundary of DDQW
typedef ALIGN(16) struct syndrome_s
{
  union {
    struct
    {
      red_r_t dup1;
      red_r_t dup2;
      uint8_t reserved[N_DDQWORDS_BITS - N_BITS];
    } v;
    uint8_t raw[N_DDQWORDS_BITS];
  } u;
} syndrome_t;

enum _seed_id
{
  G_SEED = 0,
  H_SEED = 1,
  M_SEED = 2,
  E_SEED = 3
};

typedef struct seed_s
{
  union {
    uint8_t  raw[32];
    uint64_t qw[4];
  } u;
} seed_t;

// Both keygen and encaps require double seed
typedef struct double_seed_s
{
  union {
    struct
    {
      seed_t s1;
      seed_t s2;
    } v;
    uint8_t raw[sizeof(seed_t) * 2ULL];
  } u;
} double_seed_t;

#pragma pack(pop)
