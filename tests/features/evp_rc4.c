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

/* Just checking for the existence of EVP_rc4() isn't sufficient.
 *
 * After Openssl-3.0, RC4 is only useable by loading the "legacy" provider. We
 * would either need to load the "legacy" provider in the default library context
 * (a global change) or refactor the RC4 logic to use a custom library context.
 *
 * Since RC4 is already deprecated, we should just consider it unsupported
 * if not useable with the current libcrypto configuration.
 */
int main() {
    unsigned char data[16] = { 0 };
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EXPECT_EQUAL(EVP_EncryptInit(ctx, EVP_rc4(), data, data), 1);
    return 0;
}
