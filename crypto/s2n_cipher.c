/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
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
#if defined(OPENSSL_IS_BORINGSSL) || defined(OPENSSL_IS_AWSLC)
#include <openssl/mem.h>
#endif

#include "crypto/s2n_cipher.h"

#include "utils/s2n_safety.h"

int s2n_session_key_alloc(struct s2n_session_key *key)
{
    eq_check(key->evp_cipher_ctx, NULL);
    notnull_check(key->evp_cipher_ctx = EVP_CIPHER_CTX_new());
#if defined(S2N_CIPHER_AEAD_API_AVAILABLE)
    eq_check(key->evp_aead_ctx, NULL);
    notnull_check(key->evp_aead_ctx = OPENSSL_malloc(sizeof(EVP_AEAD_CTX)));
    EVP_AEAD_CTX_zero(key->evp_aead_ctx);
#endif

    return 0;
}

int s2n_session_key_free(struct s2n_session_key *key)
{
    notnull_check(key->evp_cipher_ctx);
    EVP_CIPHER_CTX_free(key->evp_cipher_ctx);
    key->evp_cipher_ctx = NULL;
#if defined(S2N_CIPHER_AEAD_API_AVAILABLE)
    notnull_check(key->evp_aead_ctx);
    EVP_AEAD_CTX_free(key->evp_aead_ctx);
    key->evp_aead_ctx = NULL;
#endif

    return 0;
}
