/* Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0"
 *
 * Written by Nir Drucker, Shay Gueron and Dusan Kostic,
 * AWS Cryptographic Algorithms Group.
 */

#pragma once

#include <openssl/evp.h>

#include "cleanup.h"

#define MAX_AES_INVOKATION (MASK(32))

#define AES256_KEY_BYTES   (32U)
#define AES256_KEY_BITS    (AES256_KEY_BYTES * 8)
#define AES256_BLOCK_BYTES (16U)
#define AES256_ROUNDS      (14U)

typedef ALIGN(16) struct aes256_key_s {
  uint8_t raw[AES256_KEY_BYTES];
} aes256_key_t;

CLEANUP_FUNC(aes256_key, aes256_key_t)

// Using OpenSSL structures
typedef EVP_CIPHER_CTX *aes256_ks_t;

_INLINE_ ret_t aes256_key_expansion(OUT aes256_ks_t *ks,
                                    IN const aes256_key_t *key)
{
  *ks = EVP_CIPHER_CTX_new();
  if(*ks == NULL) {
    BIKE_ERROR(EXTERNAL_LIB_ERROR_OPENSSL);
  }
  if(0 == EVP_EncryptInit_ex(*ks, EVP_aes_256_ecb(), NULL, key->raw, NULL)) {
    EVP_CIPHER_CTX_free(*ks);
    BIKE_ERROR(EXTERNAL_LIB_ERROR_OPENSSL);
  }

  EVP_CIPHER_CTX_set_padding(*ks, 0);

  return SUCCESS;
}

_INLINE_ ret_t aes256_enc(OUT uint8_t *ct,
                          IN const uint8_t *pt,
                          IN const aes256_ks_t *ks)
{
  int outlen = 0;
  if(0 == EVP_EncryptUpdate(*ks, ct, &outlen, pt, AES256_BLOCK_BYTES)) {
    BIKE_ERROR(EXTERNAL_LIB_ERROR_OPENSSL);
  }
  return SUCCESS;
}

_INLINE_ void aes256_free_ks(OUT aes256_ks_t *ks)
{
  EVP_CIPHER_CTX_free(*ks);
  ks = NULL;
}
