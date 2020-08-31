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

#ifndef HEADER_BN_H
#define HEADER_BN_H

#include <openssl/ossl_typ.h>

BIGNUM *BN_new(void);
BIGNUM *BN_dup(const BIGNUM *from);
int     BN_sub(BIGNUM *r, const BIGNUM *a, const BIGNUM *b);
void    BN_clear_free(BIGNUM *a);
void    BN_free(BIGNUM *a);

#endif
