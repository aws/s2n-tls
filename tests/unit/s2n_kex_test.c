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

#include "tests/s2n_test.h"

#include "tls/s2n_kex.h"

int main(int argc, char **argv)
{
    BEGIN_TEST();

    /* Test s2n_kex_includes */
    {
        /* True if same kex */
        EXPECT_TRUE(s2n_kex_includes(NULL, NULL));
        EXPECT_TRUE(s2n_kex_includes(&s2n_rsa, &s2n_rsa));
        EXPECT_TRUE(s2n_kex_includes(&s2n_hybrid_ecdhe_kem, &s2n_hybrid_ecdhe_kem));

        /* False if different kex */
        EXPECT_FALSE(s2n_kex_includes(&s2n_rsa, &s2n_dhe));
        EXPECT_FALSE(s2n_kex_includes(&s2n_kem, &s2n_ecdhe));

        /* True if hybrid that contains */
        EXPECT_TRUE(s2n_kex_includes(&s2n_hybrid_ecdhe_kem, &s2n_ecdhe));
        EXPECT_TRUE(s2n_kex_includes(&s2n_hybrid_ecdhe_kem, &s2n_kem));

        /* False if hybrid "contains" relationship reversed */
        EXPECT_FALSE(s2n_kex_includes(&s2n_ecdhe, &s2n_hybrid_ecdhe_kem));
        EXPECT_FALSE(s2n_kex_includes(&s2n_kem, &s2n_hybrid_ecdhe_kem));

        /* False if hybrid that does not contain */
        EXPECT_FALSE(s2n_kex_includes(&s2n_hybrid_ecdhe_kem, &s2n_rsa));
        EXPECT_FALSE(s2n_kex_includes(&s2n_hybrid_ecdhe_kem, &s2n_dhe));

        /* False if one kex null */
        EXPECT_FALSE(s2n_kex_includes(&s2n_rsa, NULL));
        EXPECT_FALSE(s2n_kex_includes(NULL, &s2n_rsa));
    }

    END_TEST();
}
