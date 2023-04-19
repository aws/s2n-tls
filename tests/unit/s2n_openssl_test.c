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

#include "crypto/s2n_openssl.h"

#include "s2n_test.h"

int main(int argc, char** argv)
{
    BEGIN_TEST();

    const char* env_libcrypto = getenv("S2N_LIBCRYPTO");
    if (env_libcrypto == NULL) {
        END_TEST();
    }

    if (strcmp(env_libcrypto, "boringssl") == 0) {
        EXPECT_FALSE(s2n_libcrypto_is_awslc());
        EXPECT_TRUE(s2n_libcrypto_is_boringssl());
    } else if (strstr(env_libcrypto, "awslc") != NULL) {
        EXPECT_TRUE(s2n_libcrypto_is_awslc());
        EXPECT_FALSE(s2n_libcrypto_is_boringssl());
    } else {
        EXPECT_FALSE(s2n_libcrypto_is_awslc());
        EXPECT_FALSE(s2n_libcrypto_is_boringssl());
    }

    END_TEST();
}
