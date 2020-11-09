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

#include <cbmc_proof/nondet.h>
#include <openssl/evp.h>

void EVP_MD_CTX_set_flags(EVP_MD_CTX *ctx, int flags)
{
    assert(__CPROVER_r_ok(ctx, sizeof(*ctx)));
    ctx->flags |= flags;
}

EVP_MD_CTX *EVP_MD_CTX_new(void) {
    return malloc(sizeof(EVP_MD_CTX));
}
