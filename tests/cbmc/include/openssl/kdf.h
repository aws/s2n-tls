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

#ifndef HEADER_KDF_H
#define HEADER_KDF_H

#include <openssl/evp.h>
#include <openssl/ossl_typ.h>
#include <stdarg.h>
#include <stddef.h>
#ifdef __cplusplus
extern "C" {
#endif

/**** The legacy PKEY-based KDF API follows. ****/

#define EVP_PKEY_CTRL_TLS_MD (EVP_PKEY_ALG_CTRL)
#define EVP_PKEY_CTRL_TLS_SECRET (EVP_PKEY_ALG_CTRL + 1)
#define EVP_PKEY_CTRL_TLS_SEED (EVP_PKEY_ALG_CTRL + 2)
#define EVP_PKEY_CTRL_HKDF_MD (EVP_PKEY_ALG_CTRL + 3)
#define EVP_PKEY_CTRL_HKDF_SALT (EVP_PKEY_ALG_CTRL + 4)
#define EVP_PKEY_CTRL_HKDF_KEY (EVP_PKEY_ALG_CTRL + 5)
#define EVP_PKEY_CTRL_HKDF_INFO (EVP_PKEY_ALG_CTRL + 6)
#define EVP_PKEY_CTRL_HKDF_MODE (EVP_PKEY_ALG_CTRL + 7)
#define EVP_PKEY_CTRL_PASS (EVP_PKEY_ALG_CTRL + 8)
#define EVP_PKEY_CTRL_SCRYPT_SALT (EVP_PKEY_ALG_CTRL + 9)
#define EVP_PKEY_CTRL_SCRYPT_N (EVP_PKEY_ALG_CTRL + 10)
#define EVP_PKEY_CTRL_SCRYPT_R (EVP_PKEY_ALG_CTRL + 11)
#define EVP_PKEY_CTRL_SCRYPT_P (EVP_PKEY_ALG_CTRL + 12)
#define EVP_PKEY_CTRL_SCRYPT_MAXMEM_BYTES (EVP_PKEY_ALG_CTRL + 13)

#define EVP_PKEY_HKDEF_MODE_EXTRACT_AND_EXPAND EVP_KDF_HKDF_MODE_EXTRACT_AND_EXPAND
#define EVP_PKEY_HKDEF_MODE_EXTRACT_ONLY EVP_KDF_HKDF_MODE_EXTRACT_ONLY
#define EVP_PKEY_HKDEF_MODE_EXPAND_ONLY EVP_KDF_HKDF_MODE_EXPAND_ONLY

#define EVP_PKEY_CTX_set_hkdf_md(pctx, md) \
    EVP_PKEY_CTX_ctrl(pctx, -1, EVP_PKEY_OP_DERIVE, EVP_PKEY_CTRL_HKDF_MD, 0, ( void * )(md))

#define EVP_PKEY_CTX_set1_hkdf_salt(pctx, salt, saltlen) \
    EVP_PKEY_CTX_ctrl(pctx, -1, EVP_PKEY_OP_DERIVE, EVP_PKEY_CTRL_HKDF_SALT, saltlen, ( void * )(salt))

#define EVP_PKEY_CTX_set1_hkdf_key(pctx, key, keylen) \
    EVP_PKEY_CTX_ctrl(pctx, -1, EVP_PKEY_OP_DERIVE, EVP_PKEY_CTRL_HKDF_KEY, keylen, ( void * )(key))

#define EVP_PKEY_CTX_add1_hkdf_info(pctx, info, infolen) \
    EVP_PKEY_CTX_ctrl(pctx, -1, EVP_PKEY_OP_DERIVE, EVP_PKEY_CTRL_HKDF_INFO, infolen, ( void * )(info))

#define EVP_PKEY_CTX_hkdf_mode(pctx, mode) \
    EVP_PKEY_CTX_ctrl(pctx, -1, EVP_PKEY_OP_DERIVE, EVP_PKEY_CTRL_HKDF_MODE, mode, NULL)

#ifdef __cplusplus
}
#endif
#endif
