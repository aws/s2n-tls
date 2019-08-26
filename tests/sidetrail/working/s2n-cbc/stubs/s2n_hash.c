/*
 * Copyright 2017 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * A copy of the License is located at
 *
 *  http://aws.amazon.com/apache2.0
 *
 * or in the "license" file accompanying this file. This file is distributed
 * on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */

#include <stdint.h>
#include <stdlib.h>
#include "s2n_hash.h"
#include "../error/s2n_errno.h"
#include <smack.h>
#include "ct-verif.h"
#include "../sidetrail.h"

int s2n_hash_digest_size(s2n_hash_algorithm alg, uint8_t *out)
{
    switch (alg) {
    case S2N_HASH_NONE:     *out = 0;                    break;
    case S2N_HASH_MD5:      *out = MD5_DIGEST_LENGTH;    break;
    case S2N_HASH_SHA1:     *out = SHA_DIGEST_LENGTH;    break;
    case S2N_HASH_SHA224:   *out = SHA224_DIGEST_LENGTH; break;
    case S2N_HASH_SHA256:   *out = SHA256_DIGEST_LENGTH; break;
    case S2N_HASH_SHA384:   *out = SHA384_DIGEST_LENGTH; break;
    case S2N_HASH_SHA512:   *out = SHA512_DIGEST_LENGTH; break;
    case S2N_HASH_MD5_SHA1: *out = MD5_DIGEST_LENGTH + SHA_DIGEST_LENGTH; break;
    default:
        S2N_ERROR(S2N_ERR_HASH_INVALID_ALGORITHM);
    }
    return 0;
}

int s2n_hash_new(struct s2n_hash_state *state)
{
  return SUCCESS;
}

int s2n_hash_init(struct s2n_hash_state *state, s2n_hash_algorithm alg)
{
  __VERIFIER_ASSUME_LEAKAGE(0);
  state->alg = alg;
  state->currently_in_hash_block = 0;
  return SUCCESS;
}

int num_blocks(int numBytes) {
  /* Using div and mod directly in the stubs turned out to have significant runtime cost
   * because the backend SMT solver does not handle these non-linear operations well.
   * Instead, hardcode the div function.
   * This trades off speed for generality because we have to assert that no input is larger
   * the given bound.  Padding length cannot be more than 256, (4 SHA1 blocks). Choosing a 
   * bound much larger than this ensures that for any padding size we can see the effect on 
   * the packet.
   */
  __VERIFIER_ASSUME_LEAKAGE(0);
  if (numBytes <  1*BLOCK_SIZE) {BENIGN;return 0;}
  if (numBytes <  2*BLOCK_SIZE) return 1;
  if (numBytes <  3*BLOCK_SIZE) return 2;
  if (numBytes <  4*BLOCK_SIZE) return 3;
  if (numBytes <  5*BLOCK_SIZE) return 4;
  if (numBytes <  6*BLOCK_SIZE) return 5;
  if (numBytes <  7*BLOCK_SIZE) return 6;
  if (numBytes <  8*BLOCK_SIZE) return 7;
  if (numBytes <  9*BLOCK_SIZE) return 8;
  if (numBytes < 10*BLOCK_SIZE) return 9;
  if (numBytes < 11*BLOCK_SIZE) return 10;
  if (numBytes < 12*BLOCK_SIZE) return 11;
  if (numBytes < 13*BLOCK_SIZE) return 12;
  if (numBytes < 14*BLOCK_SIZE) return 13;
  if (numBytes < 15*BLOCK_SIZE) return 14;
  if (numBytes < 16*BLOCK_SIZE) return 15;
  if (numBytes < 17*BLOCK_SIZE) return 16;
  if (numBytes == 17*BLOCK_SIZE) return 17;
  __VERIFIER_assert(0);/* Unreachable */
}

int s2n_hash_update(struct s2n_hash_state *state, const void *data, uint32_t size)
{

  /* The __VERIFIER_assert statements give better performance but don't add to our current spec.
   * In particular, Boogie is bad about reestablishing invariants on values that have been put
   * into memory, then read back out. Adding the asserts triggers Boogie to relearn the 
   * invariant properties.
   * The proof should hold in their absense (albeit much more slowly).
   */
  /* cppcheck-suppress unsignedPositive */
   __VERIFIER_assert(size >= 0);
   __VERIFIER_assert(size <= MAX_SIZE);
   __VERIFIER_assert(state->currently_in_hash_block < BLOCK_SIZE);

   /* We model a hash function as having two forms of leakage: 
    * A per-byte-cost, which represents the cost of moving the information into the hash bufer
    * A per-block-cost, which represents the cost of compressing one hash-block using the hash fn
    * As discussed in the README, __VERIFIER_ASSUME_LEAKAGE allows us to annotate these 
    * timing costs into the stub
    */
   __VERIFIER_ASSUME_LEAKAGE(PER_BYTE_COST * size);

   state->currently_in_hash_block += size;
   int num_filled_blocks = num_blocks(state->currently_in_hash_block);
   __VERIFIER_ASSUME_LEAKAGE(num_filled_blocks * PER_BLOCK_COST);

   state->currently_in_hash_block = state->currently_in_hash_block - num_filled_blocks*BLOCK_SIZE;
   __VERIFIER_assert(state->currently_in_hash_block < BLOCK_SIZE);

   return SUCCESS;
}

int s2n_hash_digest(struct s2n_hash_state *state, void *out, uint32_t size)
{
  __VERIFIER_ASSUME_LEAKAGE(0);
  /* All the leakage comes from the hash_update we do once we've updated the size fields */

  const int MARKER_BYTE_LENGTH = 1;
  /* append the bit '1' to the message e.g. by adding 0x80 if message length is a multiple of 8 bits. */
  uint32_t min_bytes_to_add = MARKER_BYTE_LENGTH;
  min_bytes_to_add += LENGTH_FIELD_SIZE;

  int bytes_to_add;
  if(state->currently_in_hash_block + min_bytes_to_add <= BLOCK_SIZE){
    BENIGN;
    bytes_to_add = BLOCK_SIZE - state->currently_in_hash_block;
  } else {
    bytes_to_add = BLOCK_SIZE + (BLOCK_SIZE - state->currently_in_hash_block);
  }

  s2n_hash_update(state, NULL, bytes_to_add);
  return SUCCESS;
}

int s2n_hash_copy(struct s2n_hash_state *to, struct s2n_hash_state *from)
{
  __VERIFIER_ASSUME_LEAKAGE(0);
  to->alg = from->alg;
  to->currently_in_hash_block = from->currently_in_hash_block;
  return SUCCESS;
}

int s2n_hash_reset(struct s2n_hash_state *state)
{
  __VERIFIER_ASSUME_LEAKAGE(0);
  state->currently_in_hash_block = 0;
  return SUCCESS;
}

int s2n_hash_free(struct s2n_hash_state *state)
{
  return SUCCESS;
}

int s2n_hash_get_currently_in_hash_total(struct s2n_hash_state *state, uint64_t *out)
{
  *out = state->currently_in_hash_block;
  return SUCCESS;
}

