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

#include <openssl/digest.h>
#include <openssl/hkdf.h>

#define TEST_BUFFER_SIZE 64

int main()
{
    uint8_t out_key[TEST_BUFFER_SIZE] = { 0 };
    const uint8_t secret[TEST_BUFFER_SIZE] = { 0 };
    const uint8_t salt[TEST_BUFFER_SIZE] = { 0 };
    const uint8_t info[TEST_BUFFER_SIZE] = { 0 };
    const uint8_t prk[TEST_BUFFER_SIZE] = { 0 };

    HKDF(out_key, TEST_BUFFER_SIZE, EVP_sha256(),
            secret, TEST_BUFFER_SIZE,
            salt, TEST_BUFFER_SIZE,
            info, TEST_BUFFER_SIZE);

    size_t out_len = TEST_BUFFER_SIZE;
    HKDF_extract(out_key, &out_len, EVP_sha256(),
            secret, TEST_BUFFER_SIZE,
            salt, TEST_BUFFER_SIZE);

    HKDF_expand(out_key, TEST_BUFFER_SIZE, EVP_sha256(),
            prk, TEST_BUFFER_SIZE,
            info, TEST_BUFFER_SIZE);

    return 0;
}
