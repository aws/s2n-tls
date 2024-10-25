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

#include "api/s2n.h"
#include "crypto/s2n_libcrypto.h"
#include "crypto/s2n_openssl.h"
#include "crypto/s2n_pq.h"
#include "s2n_test.h"
#include "testlib/s2n_testlib.h"

int main()
{
    BEGIN_TEST();
    /* MLKEM Support was added to AWSLC when AWSLC_API_VERSION == 29 */
    if (s2n_libcrypto_is_awslc() && s2n_libcrypto_awslc_api_version() >= 30) {
        EXPECT_TRUE(s2n_libcrypto_supports_mlkem());
    } else if (s2n_libcrypto_is_awslc() && s2n_libcrypto_awslc_api_version() < 29) {
        EXPECT_FALSE(s2n_libcrypto_supports_mlkem());
    }

    END_TEST();
}
