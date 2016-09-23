/*
 * Copyright 2016 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

#include <openssl/evp.h>

#include "crypto/s2n_cipher.h"

#include "utils/s2n_safety.h"

int s2n_session_key_alloc(struct s2n_session_key *key)
{
    eq_check(key->evp_cipher_ctx, NULL);
    notnull_check(key->evp_cipher_ctx = EVP_CIPHER_CTX_new());

    return 0;
}

int s2n_session_key_free(struct s2n_session_key *key)
{
    notnull_check(key->evp_cipher_ctx);
    EVP_CIPHER_CTX_free(key->evp_cipher_ctx);
    key->evp_cipher_ctx = NULL;

    return 0;
}
