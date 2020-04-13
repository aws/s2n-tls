/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

#include <sys/param.h>
#include <stdint.h>

#include "crypto/s2n_hmac.h"

#include "tls/s2n_record.h"
#include "tls/s2n_prf.h"
#include "tls/s2n_connection.h"

#include <smack.h>
#include <smack-contracts.h>
#include "ct-verif.h"
#include "sidetrail.h"

int simple_cbc_wrapper(int currently_in_hash_block, int size, int *xor_pad, int * digest_pad)
{
  /* Even after code balancing, there is a small remaining leakage, because s2n forces an extra hash-compression
   * round by copying an extra hash block's worth of data into the hash.  This has extra cost of memcopy one
   * hash block (of data already in cache).  This could potentially be reduced by finding a better way to trigger
   * the extra hash-compression round.
   * Note that the 68 here is in LLVM time model units, which roughly correspond to cycles
   */
  __VERIFIER_ASSERT_MAX_LEAKAGE(68);

  public_in(__SMACK_value(currently_in_hash_block));
  __VERIFIER_assume(currently_in_hash_block >= 0);
  __VERIFIER_assume(currently_in_hash_block < BLOCK_SIZE);

  struct s2n_hmac_state hmac = {
    .alg = S2N_HMAC_SHA1,
    .hash_block_size = BLOCK_SIZE,
    .currently_in_hash_block = 0,
    .digest_size = SHA_DIGEST_LENGTH,
    .xor_pad_size = BLOCK_SIZE,
    .inner.alg = S2N_HASH_SHA1,
    .inner.currently_in_hash_block = 0,
    .inner_just_key.alg = S2N_HASH_SHA1,
    .inner_just_key.currently_in_hash_block = 0,
    .outer.alg = S2N_HASH_SHA1,
    .outer.currently_in_hash_block = 0,
    .outer_just_key.alg = S2N_HASH_SHA1,
    .outer_just_key.currently_in_hash_block = 0,
     .xor_pad = *xor_pad,
    //xor_pad is an array
    .digest_pad = *digest_pad
  };


  struct s2n_crypto_parameters client;
  struct s2n_connection conn = {
    .client = &client,
    .mode = S2N_SERVER
  };

  /* Data represents the decrypted data handed to the process.
   * Intentionally left non-deterministic so that the proof can handle all possible values in the buffer
   */
   //cppcheck-suppress unassignedVariable
  int data[MAX_SIZE];
  public_in(__SMACK_value(size));
  __VERIFIER_assume(size >= 0);
  __VERIFIER_assume(size <= MAX_SIZE);

  struct s2n_blob decrypted = {
    .data = data,
    .size = size,
    .allocated = 1,
  };

  return s2n_verify_cbc(&conn, &hmac, &decrypted);
}
