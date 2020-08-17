/*
 * Changes to OpenSSL version 1.1.1.
 * Copyright Amazon.com, Inc. All Rights Reserved.
 * Copyright 1995-2017 The OpenSSL Project Authors. All Rights Reserved.
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

#ifndef HEADER_EVP_H
#define HEADER_EVP_H

#include <openssl/ec.h>
#include <openssl/ossl_typ.h>
#include <stddef.h>

#define EVP_MAX_MD_SIZE 64  /* longest known is SHA512 */
#define EVP_PKEY_HKDF 1036  // reference from obj_mac.h

EVP_PKEY *    EVP_PKEY_new(void);
EC_KEY *      EVP_PKEY_get0_EC_KEY(EVP_PKEY *pkey);
int           EVP_PKEY_set1_EC_KEY(EVP_PKEY *pkey, EC_KEY *key);
void          EVP_PKEY_free(EVP_PKEY *pkey);
EVP_PKEY_CTX *EVP_PKEY_CTX_new(EVP_PKEY *pkey, ENGINE *e);
EVP_PKEY_CTX *EVP_PKEY_CTX_new_id(int id, ENGINE *e);
int           EVP_PKEY_derive_init(EVP_PKEY_CTX *ctx);
int           EVP_PKEY_sign_init(EVP_PKEY_CTX *ctx);
int  EVP_PKEY_sign(EVP_PKEY_CTX *ctx, unsigned char *sig, size_t *siglen, const unsigned char *tbs, size_t tbslen);
void EVP_PKEY_CTX_free(EVP_PKEY_CTX *ctx);
int  EVP_PKEY_CTX_ctrl(EVP_PKEY_CTX *ctx, int keytype, int optype, int cmd, int p1, void *p2);
int  EVP_PKEY_derive(EVP_PKEY_CTX *ctx, unsigned char *key, size_t *keylen);
int  EVP_PKEY_encrypt_init(EVP_PKEY_CTX *ctx);
int  EVP_PKEY_decrypt_init(EVP_PKEY_CTX *ctx);
int  EVP_PKEY_CTX_set_rsa_padding(EVP_PKEY_CTX *ctx, int pad);
int  EVP_PKEY_CTX_set_rsa_oaep_md(EVP_PKEY_CTX *ctx, const EVP_MD *md);
int  EVP_PKEY_CTX_set_rsa_mgf1_md(EVP_PKEY_CTX *ctx, const EVP_MD *md);
int  EVP_PKEY_encrypt(EVP_PKEY_CTX *ctx, unsigned char *out, size_t *outlen, const unsigned char *in, size_t inlen);
int  EVP_PKEY_decrypt(EVP_PKEY_CTX *ctx, unsigned char *out, size_t *outlen, const unsigned char *in, size_t inlen);

EVP_MD_CTX *EVP_MD_CTX_new(void);
int         EVP_MD_CTX_size(const EVP_MD_CTX *ctx);
void        EVP_MD_CTX_free(EVP_MD_CTX *ctx);
int         EVP_DigestInit_ex(EVP_MD_CTX *ctx, const EVP_MD *type, ENGINE *impl);
int         EVP_DigestUpdate(EVP_MD_CTX *ctx, const void *d, size_t cnt);
int         EVP_DigestFinal_ex(EVP_MD_CTX *ctx, unsigned char *md, unsigned int *s);
int         EVP_DigestFinal(EVP_MD_CTX *ctx, unsigned char *md, unsigned int *s);
int         EVP_DigestVerifyInit(EVP_MD_CTX *ctx, EVP_PKEY_CTX **pctx, const EVP_MD *type, ENGINE *e, EVP_PKEY *pkey);
int         EVP_DigestVerifyFinal(EVP_MD_CTX *ctx, const unsigned char *sig, size_t siglen);

EVP_CIPHER_CTX *EVP_CIPHER_CTX_new(void);
int             EVP_CipherInit_ex(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *cipher, ENGINE *impl, const unsigned char *key,
                                  const unsigned char *iv, int enc);
int             EVP_CIPHER_CTX_ctrl(EVP_CIPHER_CTX *ctx, int type, int arg, void *ptr);
void            EVP_CIPHER_CTX_free(EVP_CIPHER_CTX *ctx);
int             EVP_EncryptInit_ex(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type, ENGINE *impl, const unsigned char *key,
                                   const unsigned char *iv);
int             EVP_DecryptInit_ex(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type, ENGINE *impl, const unsigned char *key,
                                   const unsigned char *iv);
int             EVP_CipherUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl, const unsigned char *in, int inl);
int             EVP_EncryptUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl, const unsigned char *in, int inl);
int             EVP_DecryptUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl, const unsigned char *in, int inl);
int             EVP_EncryptFinal_ex(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl);
int             EVP_DecryptFinal_ex(EVP_CIPHER_CTX *ctx, unsigned char *outm, int *outl);

#define EVP_MD_CTX_create() EVP_MD_CTX_new()
#define EVP_MD_CTX_destroy(ctx) EVP_MD_CTX_free((ctx))

const EVP_CIPHER *EVP_aes_128_gcm(void);
const EVP_CIPHER *EVP_aes_192_gcm(void);
const EVP_CIPHER *EVP_aes_256_gcm(void);
const EVP_MD *    EVP_sha256(void);
const EVP_MD *    EVP_sha384(void);
const EVP_MD *    EVP_sha512(void);

int EVP_MD_size(const EVP_MD *md);

#define EVP_CTRL_INIT 0x0
#define EVP_CTRL_SET_KEY_LENGTH 0x1
#define EVP_CTRL_GET_RC2_KEY_BITS 0x2
#define EVP_CTRL_SET_RC2_KEY_BITS 0x3
#define EVP_CTRL_GET_RC5_ROUNDS 0x4
#define EVP_CTRL_SET_RC5_ROUNDS 0x5
#define EVP_CTRL_RAND_KEY 0x6
#define EVP_CTRL_PBE_PRF_NID 0x7
#define EVP_CTRL_COPY 0x8
#define EVP_CTRL_AEAD_SET_IVLEN 0x9
#define EVP_CTRL_AEAD_GET_TAG 0x10
#define EVP_CTRL_AEAD_SET_TAG 0x11
#define EVP_CTRL_AEAD_SET_IV_FIXED 0x12
#define EVP_CTRL_GCM_SET_IVLEN EVP_CTRL_AEAD_SET_IVLEN
#define EVP_CTRL_GCM_GET_TAG EVP_CTRL_AEAD_GET_TAG
#define EVP_CTRL_GCM_SET_TAG EVP_CTRL_AEAD_SET_TAG
#define EVP_CTRL_GCM_SET_IV_FIXED EVP_CTRL_AEAD_SET_IV_FIXED
#define EVP_CTRL_GCM_IV_GEN 0x13
#define EVP_CTRL_CCM_SET_IVLEN EVP_CTRL_AEAD_SET_IVLEN
#define EVP_CTRL_CCM_GET_TAG EVP_CTRL_AEAD_GET_TAG
#define EVP_CTRL_CCM_SET_TAG EVP_CTRL_AEAD_SET_TAG
#define EVP_CTRL_CCM_SET_IV_FIXED EVP_CTRL_AEAD_SET_IV_FIXED
#define EVP_CTRL_CCM_SET_L 0x14
#define EVP_CTRL_CCM_SET_MSGLEN 0x15

#define EVP_PKEY_OP_UNDEFINED 0
#define EVP_PKEY_OP_PARAMGEN (1 << 1)
#define EVP_PKEY_OP_KEYGEN (1 << 2)
#define EVP_PKEY_OP_SIGN (1 << 3)
#define EVP_PKEY_OP_VERIFY (1 << 4)
#define EVP_PKEY_OP_VERIFYRECOVER (1 << 5)
#define EVP_PKEY_OP_SIGNCTX (1 << 6)
#define EVP_PKEY_OP_VERIFYCTX (1 << 7)
#define EVP_PKEY_OP_ENCRYPT (1 << 8)
#define EVP_PKEY_OP_DECRYPT (1 << 9)
#define EVP_PKEY_OP_DERIVE (1 << 10)

#define EVP_PKEY_ALG_CTRL 0x1000

#endif
