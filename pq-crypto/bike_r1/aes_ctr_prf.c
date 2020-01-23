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

#include "aes_ctr_prf.h"
#include "utilities.h"
#include <string.h>

ret_t
init_aes_ctr_prf_state(OUT aes_ctr_prf_state_t *s,
                       IN const uint32_t        max_invokations,
                       IN const seed_t *seed)
{
  if(0 == max_invokations)
  {
    BIKE_ERROR(E_AES_CTR_PRF_INIT_FAIL);
  }

  // Set the key schedule (from seed).
  // Make sure the size matches the AES256 key size
  DEFER_CLEANUP(aes256_key_t key, aes256_key_cleanup);
  bike_static_assert(sizeof(seed->u) == sizeof(key.raw),
                     seed_size_equals_ky_size);
  memcpy(key.raw, seed->u.raw, sizeof(key.raw));

  GUARD(aes256_key_expansion(&s->ks, &key));

  // Initialize buffer and counter
  s->ctr.u.qw[0]    = 0;
  s->ctr.u.qw[1]    = 0;
  s->buffer.u.qw[0] = 0;
  s->buffer.u.qw[1] = 0;

  s->pos             = AES256_BLOCK_SIZE;
  s->rem_invokations = max_invokations;

  SEDMSG("    Init aes_prf_ctr state:\n");
  SEDMSG("      s.pos = %d\n", s->pos);
  SEDMSG("      s.rem_invokations = %u\n", s->rem_invokations);
  SEDMSG("      s.ctr = 0x");

  return SUCCESS;
}

_INLINE_ ret_t
perform_aes(OUT uint8_t *ct, IN OUT aes_ctr_prf_state_t *s)
{
  // Ensure that the CTR is big enough
  bike_static_assert(
      ((sizeof(s->ctr.u.qw[0]) == 8) && (BIT(33) >= MAX_AES_INVOKATION)),
      ctr_size_is_too_small);

  if(0 == s->rem_invokations)
  {
    return E_AES_OVER_USED;
  }

  GUARD(aes256_enc(ct, s->ctr.u.bytes, &s->ks));

  s->ctr.u.qw[0]++;
  s->rem_invokations--;

  return SUCCESS;
}

ret_t
aes_ctr_prf(OUT uint8_t *a, IN OUT aes_ctr_prf_state_t *s, IN const uint32_t len)
{
  // When Len is smaller than whats left in the buffer
  // No need in additional AES
  if((len + s->pos) <= AES256_BLOCK_SIZE)
  {
    memcpy(a, &s->buffer.u.bytes[s->pos], len);
    s->pos += len;

    return SUCCESS;
  }

  // If s.pos != AES256_BLOCK_SIZE then copy whats left in the buffer
  // Else copy zero bytes
  uint32_t idx = AES256_BLOCK_SIZE - s->pos;
  memcpy(a, &s->buffer.u.bytes[s->pos], idx);

  // Init s.pos
  s->pos = 0;

  // Copy full AES blocks
  while((len - idx) >= AES256_BLOCK_SIZE)
  {
    GUARD(perform_aes(&a[idx], s));
    idx += AES256_BLOCK_SIZE;
  }

  GUARD(perform_aes(s->buffer.u.bytes, s));

  // Copy the tail
  s->pos = len - idx;
  memcpy(&a[idx], s->buffer.u.bytes, s->pos);

  return SUCCESS;
}
