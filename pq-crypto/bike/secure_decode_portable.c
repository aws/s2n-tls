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

#include "decode.h"
#include "utilities.h"
#include <string.h>

EXTERNC void
compute_counter_of_unsat(OUT uint8_t      upc[N_BITS],
                         IN const uint8_t s[N_BITS],
                         IN const compressed_idx_dv_t *inv_h0_compressed,
                         IN const compressed_idx_dv_t *inv_h1_compressed)
{
  uint32_t i = 0, j = 0, mask[2] = {0}, pos[2] = {0};

  memset(upc, 0, N_BITS);

  for(j = 0; j < FAKE_DV; j++)
  {
    // It is faster (by 5M cycles) to have one loop instead of two.
    mask[0] = inv_h0_compressed->val[j].used;
    mask[1] = inv_h1_compressed->val[j].used;
    pos[0]  = inv_h0_compressed->val[j].val;
    pos[1]  = inv_h1_compressed->val[j].val;
    for(i = 0; i < R_BITS; i++)
    {
      upc[i] += (s[i + pos[0]] & mask[0]);
      upc[R_BITS + i] += (s[i + pos[1]] & mask[1]);
    }
  }
}

EXTERNC void
find_error1(IN OUT e_t *e,
            OUT e_t *black_e,
            OUT e_t *gray_e,
            IN const uint8_t *upc,
            IN const uint32_t black_th,
            IN const uint32_t gray_th)
{
  uint8_t  bit = 1, black_acc = 0, gray_acc = 0;
  uint8_t  val = 0, mask = 0;
  uint32_t byte_itr = 0;

  for(uint64_t j = 0; j < N0; j++)
  {
    val  = upc[j * R_BITS];
    mask = secure_l32_mask(val, black_th);
    black_acc |= (bit & mask);

    // Update the gray list only if not in the black list
    val &= (~mask);

    mask = secure_l32_mask(val, gray_th);
    gray_acc |= (bit & mask);

    for(int i = R_BITS - 1; i > 0; i--)
    {
      if(bit == 0x80)
      {
        e->raw[byte_itr] ^= black_acc;
        black_e->raw[byte_itr] = black_acc;
        gray_e->raw[byte_itr]  = gray_acc;
        byte_itr++;

        bit       = 1;
        black_acc = 0;
        gray_acc  = 0;
      }
      else
      {
        bit <<= 1;
      }

      val  = upc[i + (j * R_BITS)];
      mask = secure_l32_mask(val, black_th);
      black_acc |= (bit & mask);

      // Update the gray list only if not in the black list
      val &= (~mask);

      mask = secure_l32_mask(val, gray_th);
      gray_acc |= (bit & mask);
    }
    bit <<= 1;
  }

  // Final bytes
  e->raw[byte_itr] ^= black_acc;
  black_e->raw[byte_itr] = black_acc;
  gray_e->raw[byte_itr]  = gray_acc;
}

EXTERNC void
find_error2(IN OUT e_t *e,
            IN e_t * pos_e,
            IN const uint8_t *upc,
            IN const uint32_t threshold)
{
  uint8_t  bit      = 1;
  uint8_t  pos_acc  = 0;
  uint32_t byte_itr = 0;

  for(uint64_t j = 0; j < N0; j++)
  {
    uint8_t mask = secure_l32_mask(upc[j * R_BITS], threshold);
    pos_acc |= (bit & mask);

    for(int i = R_BITS - 1; i > 0; i--)
    {
      if(bit == 0x80)
      {
        e->raw[byte_itr] ^= (pos_e->raw[byte_itr] & pos_acc);
        byte_itr++;

        bit     = 1;
        pos_acc = 0;
      }
      else
      {
        bit <<= 1;
      }

      mask = secure_l32_mask(upc[i + (j * R_BITS)], threshold);
      pos_acc |= (bit & mask);
    }
    bit <<= 1;
  }

  // Final byte
  e->raw[byte_itr] ^= (pos_e->raw[byte_itr] & pos_acc);
}
