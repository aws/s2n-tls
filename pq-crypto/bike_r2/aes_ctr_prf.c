/* Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0"
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

  bike_static_assert(sizeof(*seed) == sizeof(key.raw), seed_size_equals_ky_size);
  memcpy(key.raw, seed->raw, sizeof(key.raw));

  POSIX_GUARD(aes256_key_expansion(&s->ks_ptr, &key));

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
  SEDMSG("      s.ctr = 0x\n");

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
    BIKE_ERROR(E_AES_OVER_USED);
  }

  POSIX_GUARD(aes256_enc(ct, s->ctr.u.bytes, &s->ks_ptr));

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
    POSIX_GUARD(perform_aes(&a[idx], s));
    idx += AES256_BLOCK_SIZE;
  }

  POSIX_GUARD(perform_aes(s->buffer.u.bytes, s));

  // Copy the tail
  s->pos = len - idx;
  memcpy(&a[idx], s->buffer.u.bytes, s->pos);

  return SUCCESS;
}
