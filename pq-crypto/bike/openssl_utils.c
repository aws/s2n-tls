/***************************************************************************
* Additional implementation of "BIKE: Bit Flipping Key Encapsulation". 
* Copyright 2017 Amazon.com, Inc. or its affiliates. All Rights Reserved.
*
* Written by Nir Drucker and Shay Gueron
* AWS Cryptographic Algorithms Group
* (ndrucker@amazon.com, gueron@amazon.com)
*
* The license is detailed in the file LICENSE.txt, and applies to this file.
* ***************************************************************************/

#include "openssl_utils.h"
#include "utilities.h"
#include "openssl/bn.h"
#include <string.h>
#include <assert.h>

// Perform a cyclic product by using OpenSSL
_INLINE_ status_t ossl_cyclic_product(OUT BIGNUM *r,
                                        IN const BIGNUM *a,
                                        IN const BIGNUM *b,
                                        BN_CTX *bn_ctx) {
   status_t res = SUCCESS;
   BIGNUM *m = BN_CTX_get(bn_ctx);
   if (NULL == m) {
      ERR(EXTERNAL_LIB_ERROR_OPENSSL, res, EXIT);
   }

   // m = x^PARAM_R - 1
   if ((BN_set_bit(m, R_BITS) == 0) || (BN_set_bit(m, 0) == 0)) {
      ERR(EXTERNAL_LIB_ERROR_OPENSSL, res, EXIT);
   }

   // r = a*b mod m
   if (BN_GF2m_mod_mul(r, a, b, m, bn_ctx) == 0) {
      ERR(EXTERNAL_LIB_ERROR_OPENSSL, res, EXIT);
   }

EXIT:
   return res;
}

_INLINE_ status_t invert_poly(OUT BIGNUM *r,
                                IN const BIGNUM *a,
                                BN_CTX *bn_ctx) {
   status_t res = SUCCESS;
   BIGNUM *m = BN_CTX_get(bn_ctx);

   if (NULL == m) {
      ERR(EXTERNAL_LIB_ERROR_OPENSSL, res, EXIT);
   }

   // m = x^PARAM_R - 1
   if ((BN_set_bit(m, R_BITS) == 0) ||
       (BN_set_bit(m, 0) == 0)) {
      ERR(EXTERNAL_LIB_ERROR_OPENSSL, res, EXIT);
   }

   // r = a*b mod m
   if (BN_GF2m_mod_inv(r, a, m, bn_ctx) == 0) {
      ERR(EXTERNAL_LIB_ERROR_OPENSSL, res, EXIT);
   }

EXIT:

   return res;
}

// Loading numbers into OpenSSL should be done in Big Endian representation,
// therefore the byte order of a number should be reversed
_INLINE_ void reverse_endian(OUT uint8_t *res,
                             IN const uint8_t *in,
                             IN const uint32_t n) {
   uint32_t i;
   uint64_t tmp;

   for (i = 0; i < (n / 2); i++) {
      tmp = in[i];
      res[i] = in[n - 1 - i];
      res[n - 1 - i] = tmp;
   }

   // If the number of blocks is odd swap also the middle block
   if (n % 2) {
      res[i] = in[i];
   }
}

_INLINE_ status_t ossl_bn2bin(OUT uint8_t *out,
                                IN const BIGNUM *in,
                                IN const uint32_t size) 
{
    assert(size <= N_SIZE);
    uint8_t be_tmp[N_SIZE] = {0};

    memset(out, 0, size);

    if (BN_bn2bin(in, be_tmp) == 0) {
        return EXTERNAL_LIB_ERROR_OPENSSL;
    }
    reverse_endian(out, be_tmp, BN_num_bytes(in));

    return SUCCESS;
}

_INLINE_ status_t ossl_bin2bn(IN BIGNUM *out,
                                OUT const uint8_t *in,
                                IN const uint32_t size) 
{
    assert(size <= N_SIZE);
    uint8_t be_tmp[N_SIZE] = {0};

    reverse_endian(be_tmp, in, size);

    if (BN_bin2bn(be_tmp, size, out) == 0) {
        return EXTERNAL_LIB_ERROR_OPENSSL;
    }

    return SUCCESS;
}

status_t ossl_add(OUT uint8_t res_bin[R_SIZE],
                    IN const uint8_t a_bin[R_SIZE],
                    IN const uint8_t b_bin[R_SIZE]) {
   status_t res = SUCCESS;
   BN_CTX *bn_ctx = BN_CTX_new();
   BIGNUM *r = NULL;
   BIGNUM *a = NULL;
   BIGNUM *b = NULL;

   if (NULL == bn_ctx) {
      ERR(EXTERNAL_LIB_ERROR_OPENSSL, res, EXIT);
   }

   BN_CTX_start(bn_ctx);

   r = BN_CTX_get(bn_ctx);
   a = BN_CTX_get(bn_ctx);
   b = BN_CTX_get(bn_ctx);

   if ((NULL == r) || (NULL == a) || (NULL == b)) {
      ERR(EXTERNAL_LIB_ERROR_OPENSSL, res, EXIT);
   }

   GUARD(ossl_bin2bn(a, a_bin, R_SIZE), res, EXIT);
   GUARD(ossl_bin2bn(b, b_bin, R_SIZE), res, EXIT);

   if (BN_GF2m_add(r, a, b) == 0) {
      ERR(EXTERNAL_LIB_ERROR_OPENSSL, res, EXIT);
   }

   GUARD(ossl_bn2bin(res_bin, r, R_SIZE), res, EXIT);

EXIT:
   if (bn_ctx) {
      BN_CTX_end(bn_ctx);
      BN_CTX_free(bn_ctx);
   }

   return res;
}

// Perform a cyclic product by using OpenSSL
status_t cyclic_product(OUT uint8_t res_bin[R_SIZE],
                          IN const uint8_t a_bin[R_SIZE],
                          IN const uint8_t b_bin[R_SIZE]) {
   status_t res = SUCCESS;
   BN_CTX *bn_ctx = BN_CTX_new();
   BIGNUM *r = NULL;
   BIGNUM *a = NULL;
   BIGNUM *b = NULL;

   if (NULL == bn_ctx) {
      ERR(EXTERNAL_LIB_ERROR_OPENSSL, res, EXIT);
   }

   BN_CTX_start(bn_ctx);

   r = BN_CTX_get(bn_ctx);
   a = BN_CTX_get(bn_ctx);
   b = BN_CTX_get(bn_ctx);

   if ((NULL == r) || (NULL == a) || (NULL == b)) {
      ERR(EXTERNAL_LIB_ERROR_OPENSSL, res, EXIT);
   }

   GUARD(ossl_bin2bn(a, a_bin, R_SIZE), res, EXIT);
   GUARD(ossl_bin2bn(b, b_bin, R_SIZE), res, EXIT);
   GUARD(ossl_cyclic_product(r, a, b, bn_ctx), res, EXIT);
   GUARD(ossl_bn2bin(res_bin, r, R_SIZE), res, EXIT);

EXIT:
   if (bn_ctx) {
      BN_CTX_end(bn_ctx);
      BN_CTX_free(bn_ctx);
   }

   return res;
}

status_t ossl_split_polynomial(OUT uint8_t e0_bin[R_SIZE],
                                 OUT uint8_t e1_bin[R_SIZE],
                                 IN const uint8_t e_bin[N_SIZE]) {
   status_t res = SUCCESS;
   BN_CTX *bn_ctx = BN_CTX_new();
   BIGNUM *e = NULL;
   BIGNUM *e0 = NULL;
   BIGNUM *e1 = NULL;
   BIGNUM *mid = NULL;

   if (NULL == bn_ctx) {
      ERR(EXTERNAL_LIB_ERROR_OPENSSL, res, EXIT);
   }

   BN_CTX_start(bn_ctx);

   e = BN_CTX_get(bn_ctx);
   e0 = BN_CTX_get(bn_ctx);
   e1 = BN_CTX_get(bn_ctx);
   mid = BN_CTX_get(bn_ctx);

   if ((NULL == e) || (NULL == e0) || (NULL == e1) || (NULL == mid)) {
      ERR(EXTERNAL_LIB_ERROR_OPENSSL, res, EXIT);
   }

   GUARD(ossl_bin2bn(e, e_bin, N_SIZE), res, EXIT);

   // Split e to e0 and e1
   if ((BN_set_bit(mid, R_BITS) == 0) ||
       (BN_mod(e0, e, mid, bn_ctx) == 0) ||
       (BN_rshift(e1, e, R_BITS) == 0)) {
      ERR(EXTERNAL_LIB_ERROR_OPENSSL, res, EXIT);
   }

   GUARD(ossl_bn2bin(e0_bin, e0, R_SIZE), res, EXIT);
   GUARD(ossl_bn2bin(e1_bin, e1, R_SIZE), res, EXIT);

EXIT:
   if (bn_ctx) {
      BN_CTX_end(bn_ctx);
      BN_CTX_free(bn_ctx);
   }

   return res;
}

// Perform a cyclic product by using OpenSSL
status_t mod_inv(OUT uint8_t res_bin[R_SIZE],
                 IN const uint8_t a_bin[R_SIZE]) {
   status_t res = SUCCESS;
   BN_CTX *bn_ctx = BN_CTX_new();
   BIGNUM *r = NULL;
   BIGNUM *a = NULL;

   if (NULL == bn_ctx) {
      ERR(EXTERNAL_LIB_ERROR_OPENSSL, res, EXIT);
   }

   BN_CTX_start(bn_ctx);

   r = BN_CTX_get(bn_ctx);
   a = BN_CTX_get(bn_ctx);

   if ((NULL == r) || (NULL == a)) {
      ERR(EXTERNAL_LIB_ERROR_OPENSSL, res, EXIT);
   }

   GUARD(ossl_bin2bn(a, a_bin, R_SIZE), res, EXIT);
   GUARD(invert_poly(r, a, bn_ctx), res, EXIT);
   GUARD(ossl_bn2bin(res_bin, r, R_SIZE), res, EXIT);

EXIT:
   if (bn_ctx) {
      BN_CTX_end(bn_ctx);
      BN_CTX_free(bn_ctx);
   }

   return res;
}
