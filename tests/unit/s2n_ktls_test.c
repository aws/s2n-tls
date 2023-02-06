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

#include "crypto/s2n_cipher.h"
#include "s2n_test.h"

int main(int argc, char **argv)
{
    BEGIN_TEST();

    /* ktls_supported ciphers */
    {
        struct s2n_cipher cipher = s2n_aes128_gcm;
        EXPECT_TRUE(cipher.ktls_supported);

        cipher = s2n_aes256_gcm;
        EXPECT_FALSE(cipher.ktls_supported);

        cipher = s2n_tls13_aes128_gcm;
        EXPECT_FALSE(cipher.ktls_supported);

        cipher = s2n_tls13_aes256_gcm;
        EXPECT_FALSE(cipher.ktls_supported);

        cipher = s2n_chacha20_poly1305;
        EXPECT_FALSE(cipher.ktls_supported);
    };

    END_TEST();
}
