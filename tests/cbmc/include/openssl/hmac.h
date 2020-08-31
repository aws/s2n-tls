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

/* Empty header. Necessary just because it is included in cipher_openssl.c */

#ifndef HEADER_HMAC_H
#define HEADER_HMAC_H

struct hmac_ctx_st {
    const EVP_MD *md;
    EVP_MD_CTX *  md_ctx;
    EVP_MD_CTX *  i_ctx;
    EVP_MD_CTX *  o_ctx;
    bool          is_initialized;
};

#endif
