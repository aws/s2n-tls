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

/*
 * This feature probe checks if the linked libcrypto has "provider" support:
 * https://docs.openssl.org/3.4/man7/provider/
 * Fetching algorithms from providers:
 * https://docs.openssl.org/3.4/man7/ossl-guide-libcrypto-introduction/#algorithm-fetching
 */

#include <openssl/evp.h>

int main()
{
    /* Supports fetching hash algorithms */
    EVP_MD *md = EVP_MD_fetch(NULL, NULL, NULL);
    EVP_MD_free(md);

    /* Supports property queries for pkey context implicit fetching */
    EVP_PKEY_CTX *pkey_ctx = EVP_PKEY_CTX_new_from_pkey(NULL, NULL, NULL);

    return 0;
}
