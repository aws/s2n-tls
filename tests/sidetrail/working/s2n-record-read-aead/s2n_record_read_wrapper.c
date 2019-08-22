/*
 * Copyright 2014 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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
#include <stdlib.h>

#include "crypto/s2n_hmac.h"

#include "tls/s2n_record.h"
#include "tls/s2n_prf.h"
#include "tls/s2n_connection.h"

#include <smack.h>
#include <smack-contracts.h>
#include "ct-verif.h"
#include "sidetrail.h"
#include "utils/s2n_safety.h"
#include "tls/s2n_cipher_suites.h"
#include "utils/s2n_blob.h"
#include "crypto/s2n_cipher.h"

int s2n_record_parse_aead(
    const struct s2n_cipher_suite *cipher_suite,
    struct s2n_connection *conn,
    uint8_t content_type,
    uint16_t encrypted_length,
    uint8_t * implicit_iv,
    struct s2n_hmac_state *mac,
    uint8_t * sequence_number,
    struct s2n_session_key *session_key);


#define DECRYPT_COST 10
#define IV_SIZE 16
#define MAX_SIZE 1024
#define TAG_SIZE 16

int decrypt_aead(struct s2n_session_key *session_key,
		struct s2n_blob* iv,
		struct s2n_blob* aad,
		struct s2n_blob* in,
		struct s2n_blob* out)

{
  int size = in->size;
  __VERIFIER_ASSUME_LEAKAGE(size * DECRYPT_COST);
  out->data = malloc(size);
  return 0;
}

int s2n_increment_sequence_number(uint8_t * sequence_number){
  __VERIFIER_ASSUME_LEAKAGE(0);
  return 0;
}

int s2n_record_parse_wrapper(int *xor_pad,
			     int *digest_pad,
			     int padding_length,
			     int encrypted_length,
			     uint8_t content_type,
			     int flags
)
{
  __VERIFIER_ASSERT_MAX_LEAKAGE(10);
  __VERIFIER_assume(encrypted_length > 0);
  public_in(__SMACK_value(padding_length));
  public_in(__SMACK_value(encrypted_length));
  public_in(__SMACK_value(flags));
  
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
    .digest_pad = *digest_pad
  };

  
  struct s2n_cipher aead_cipher = {
    .type = S2N_AEAD,
    .io.aead.decrypt = decrypt_aead,
    .io.aead.record_iv_size = IV_SIZE,
    .io.aead.fixed_iv_size = IV_SIZE,
    .io.aead.tag_size = TAG_SIZE,
  };
  
  struct s2n_record_algorithm record_algorithm = {
    .cipher = &aead_cipher,
    .flags = flags
  };
  
  struct s2n_cipher_suite cipher_suite = {
    .record_alg = &record_algorithm,
  };

  /* cppcheck-suppress unassignedVariable */
  uint8_t data1[MAX_SIZE];
  /* cppcheck-suppress unassignedVariable */
  uint8_t data2[MAX_SIZE];
  
  struct s2n_connection conn = {
    .actual_protocol_version = S2N_TLS10,
    .in = {
      .read_cursor = 0,
      .write_cursor = MAX_SIZE,
      .blob = {
	.data = data1,
	.size = MAX_SIZE,
      },
    },
    .header_in = {
      .read_cursor = 0,
      .write_cursor = S2N_TLS_RECORD_HEADER_LENGTH,
      .blob = {
	.data = data2,
	.size = MAX_SIZE,
      },
    },
  };

  uint8_t sequence_number[S2N_TLS_SEQUENCE_NUM_LEN];
  struct s2n_session_key session_key;
  uint8_t implicit_iv[S2N_TLS_MAX_IV_LEN];

  return s2n_record_parse_aead(&cipher_suite, &conn, content_type, encrypted_length, implicit_iv, &hmac, sequence_number, &session_key);
}
