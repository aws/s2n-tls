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

#include "cleanup.h"
#include <openssl/evp.h>

#define MAX_AES_INVOKATION (MASK(32))

#define AES256_KEY_SIZE   (32ULL)
#define AES256_KEY_BITS   (AES256_KEY_SIZE * 8)
#define AES256_BLOCK_SIZE (16ULL)
#define AES256_ROUNDS     (14ULL)

typedef ALIGN(16) struct aes256_key_s
{
  uint8_t raw[AES256_KEY_SIZE];
} aes256_key_t;

_INLINE_ void
aes256_key_cleanup(aes256_key_t *o)
{
  secure_clean(o->raw, sizeof(*o));
}

// Using OpenSSL structures
typedef EVP_CIPHER_CTX *aes256_ks_t;

_INLINE_ ret_t
aes256_key_expansion(OUT aes256_ks_t *ks, IN const aes256_key_t *key)
{
  *ks = EVP_CIPHER_CTX_new();
  if(*ks == NULL)
  {
    BIKE_ERROR(EXTERNAL_LIB_ERROR_OPENSSL);
  }
  if(0 == EVP_EncryptInit_ex(*ks, EVP_aes_256_ecb(), NULL, key->raw, NULL))
  {
    EVP_CIPHER_CTX_free(*ks);
    BIKE_ERROR(EXTERNAL_LIB_ERROR_OPENSSL);
  }

  EVP_CIPHER_CTX_set_padding(*ks, 0);

  return SUCCESS;
}

_INLINE_ ret_t
aes256_enc(OUT uint8_t *ct, IN const uint8_t *pt, IN const aes256_ks_t *ks)
{
  int outlen = 0;
  if(0 == EVP_EncryptUpdate(*ks, ct, &outlen, pt, AES256_BLOCK_SIZE))
  {
    BIKE_ERROR(EXTERNAL_LIB_ERROR_OPENSSL);
  }
  return SUCCESS;
}

_INLINE_ void
aes256_free_ks(OUT aes256_ks_t *ks)
{
  EVP_CIPHER_CTX_free(*ks);
  ks = NULL;
}
