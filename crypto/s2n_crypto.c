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

#include <s2n.h>
#include "utils/s2n_safety.h"
#include "stuffer/s2n_stuffer.h"
#include "crypto/s2n_pkey.h"

int get_private_key_pem(struct s2n_pkey* pkey, const char *private_key_pem, uint32_t private_key_pem_length) {
  /* Put the private key pem in a stuffer */
  DEFER_CLEANUP(struct s2n_stuffer key_in_stuffer = {{0}}, s2n_stuffer_free);
  DEFER_CLEANUP(struct s2n_stuffer key_out_stuffer = {{0}}, s2n_stuffer_free);
  GUARD(s2n_stuffer_alloc_ro_from_string(&key_in_stuffer, private_key_pem));
  GUARD(s2n_stuffer_growable_alloc(&key_out_stuffer, strlen(private_key_pem)));

  /* Convert pem to asn1 and asn1 to the private key. Handles both PKCS#1 and PKCS#8 formats */
  struct s2n_blob key_blob = {0};
  GUARD(s2n_stuffer_private_key_from_pem(&key_in_stuffer, &key_out_stuffer));
  key_blob.size = s2n_stuffer_data_available(&key_out_stuffer);
  key_blob.data = s2n_stuffer_raw_read(&key_out_stuffer, key_blob.size);
  notnull_check(key_blob.data);

  /* Get key type and create appropriate key context */
  GUARD(s2n_pkey_zero_init(pkey));
  GUARD(s2n_asn1der_to_private_key(pkey, &key_blob));

  return 0;
}

/**
 *
 * @param[in]  key           Byte array contains the private key. Note that it should end with '/0'
 * @param[in]  key_length    Length of the key byte array, expected to be positive number
 * @param[in]  in            Byte array contains the encrypted data
 * @param[in]  in_length     Length of the encrypted data, expected to be positive number
 * @param[out] out           Buffer to hold the decrypted data
 * @param[in]  out_length    Length of the buffer length, expected to be positive number
 * @return                   Return 0 if succeeded, otherwise return -1
 */
int s2n_decrypt_with_key(const char *key, uint32_t key_length, uint8_t *in, uint32_t in_length, uint8_t *out, uint32_t out_length)
{
  // the pointers cannot be null
  notnull_check(key);
  notnull_check(in);
  notnull_check(out);

  // the length should be positive
  gte_check(key_length, 0);
  gte_check(in_length, 0);
  gte_check(out_length, 0);

  // the last byte of the key should be a null byte
  eq_check('\0', key[key_length - 1]);

  // Get key type and create appropriate key context
  DEFER_CLEANUP(struct s2n_pkey pkey = {{{0}}}, s2n_pkey_free);
  GUARD(get_private_key_pem(&pkey, key, key_length));

  struct s2n_blob in_blob = {0};
  in_blob.data = in;
  in_blob.size = in_length;

  struct s2n_blob out_blob = {0};
  out_blob.data = out;
  out_blob.size = out_length;

  // decrypt
  if (0 != s2n_pkey_decrypt(&pkey, &in_blob, &out_blob)) {
    return -1;
  }

  return 0;
}
