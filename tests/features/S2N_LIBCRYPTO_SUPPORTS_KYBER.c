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
#include <openssl/nid.h>

int main()
{
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_KEM, NULL);
    if (ctx == NULL) {
        return 1;
    }
    if (!EVP_PKEY_CTX_kem_set_params(ctx, NID_KYBER512_R3)
            || !EVP_PKEY_CTX_kem_set_params(ctx, NID_KYBER768_R3)
            || !EVP_PKEY_CTX_kem_set_params(ctx, NID_KYBER1024_R3)) {
        EVP_PKEY_CTX_free(ctx);
        return 1;
    }
    EVP_PKEY_CTX_free(ctx);
    return 0;
}
