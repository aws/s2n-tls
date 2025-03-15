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
 * Not all libcryptos support RAND_priv_bytes.
 *
 * Note: the existence of RAND_priv_bytes() does NOT mean that the libcrypto
 * actually supports a separate, private source of randomness. Some libcryptos
 * like awslc just alias RAND_priv_bytes to RAND_bytes.
 */

#include <openssl/rand.h>

int main()
{
    uint8_t bytes[10] = { 0 };
    RAND_priv_bytes(bytes, sizeof(bytes));
    return 0;
}
