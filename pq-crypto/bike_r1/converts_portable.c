/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

// Convert a sequence of uint8_t elements which fully uses all 8-bits of
// an uint8_t element to a sequence of uint8_t which uses just a single
// bit per byte (either 0 or 1).
EXTERNC void
convert_to_redundant_rep(OUT uint8_t *out,
                         IN const uint8_t *in,
                         IN const uint64_t len)
{
  uint8_t tmp;
  for(uint32_t i = 0; i < (len / 8); i++)
  {
    tmp = in[i];
    for(uint8_t j = 0; j < 8; j++)
    {
      out[8 * i + j] |= (tmp & 0x1);
      tmp >>= 1;
    }
  }

  // Convert the reminder
  tmp = in[len / 8];
  for(uint32_t j = 8 * (len / 8); j < len; j++)
  {
    out[j] |= (tmp & 0x1);
    tmp >>= 1;
  }
}

EXTERNC uint64_t
count_ones(IN const uint8_t *in, IN const uint32_t len)
{
  uint64_t acc = 0;
  for(uint32_t i = 0; i < len; i++)
  {
    acc += __builtin_popcount(in[i]);
  }

  return acc;
}
