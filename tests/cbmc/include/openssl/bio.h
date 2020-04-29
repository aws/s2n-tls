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

#ifndef HEADER_BIO_H
#define HEADER_BIO_H

#ifndef OPENSSL_NO_STDIO
#    include <stdio.h>
#endif
#include <stdarg.h>

#ifdef __cplusplus
extern "C" {
#endif
#include <openssl/ossl_typ.h>

typedef int pem_password_cb(char *buf, int size, int rwflag, void *u);

BIO *BIO_new_mem_buf(const void *buf, signed int len);

EVP_PKEY *PEM_read_bio_PUBKEY(BIO *bp, EVP_PKEY **x, pem_password_cb *cb, void *u);

EVP_PKEY *PEM_read_bio_PrivateKey(BIO *bp, EVP_PKEY **x, pem_password_cb *cb, void *u);

int BIO_free(BIO *a);

#ifdef __cplusplus
}
#endif
#endif
