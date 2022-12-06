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

#include "tls/s2n_ecc_preferences.h"

#include "s2n_test.h"
#include "tls/s2n_tls_parameters.h"

int main(int argc, char **argv)
{
    BEGIN_TEST();
    EXPECT_SUCCESS(s2n_disable_tls13_in_test());

    /* Tests for s2n_ecc_preferences_includes */
    {
        EXPECT_FALSE(s2n_ecc_preferences_includes_curve(NULL, TLS_EC_CURVE_SECP_256_R1));

        EXPECT_TRUE(s2n_ecc_preferences_includes_curve(&s2n_ecc_preferences_20140601, TLS_EC_CURVE_SECP_256_R1));
        EXPECT_TRUE(s2n_ecc_preferences_includes_curve(&s2n_ecc_preferences_20140601, TLS_EC_CURVE_SECP_384_R1));
        EXPECT_FALSE(s2n_ecc_preferences_includes_curve(&s2n_ecc_preferences_20140601, TLS_EC_CURVE_ECDH_X25519));

        EXPECT_TRUE(s2n_ecc_preferences_includes_curve(&s2n_ecc_preferences_20200310, TLS_EC_CURVE_SECP_256_R1));
        EXPECT_TRUE(s2n_ecc_preferences_includes_curve(&s2n_ecc_preferences_20200310, TLS_EC_CURVE_SECP_384_R1));
#if EVP_APIS_SUPPORTED
        EXPECT_TRUE(s2n_ecc_preferences_includes_curve(&s2n_ecc_preferences_20200310, TLS_EC_CURVE_ECDH_X25519));
#else
        EXPECT_FALSE(s2n_ecc_preferences_includes_curve(&s2n_ecc_preferences_20200310, TLS_EC_CURVE_ECDH_X25519));
#endif

        EXPECT_TRUE(s2n_ecc_preferences_includes_curve(&s2n_ecc_preferences_20201021, TLS_EC_CURVE_SECP_256_R1));
        EXPECT_TRUE(s2n_ecc_preferences_includes_curve(&s2n_ecc_preferences_20201021, TLS_EC_CURVE_SECP_384_R1));
        EXPECT_TRUE(s2n_ecc_preferences_includes_curve(&s2n_ecc_preferences_20201021, TLS_EC_CURVE_SECP_521_R1));
        EXPECT_FALSE(s2n_ecc_preferences_includes_curve(&s2n_ecc_preferences_20201021, TLS_EC_CURVE_ECDH_X25519));
    };

    END_TEST();
}
