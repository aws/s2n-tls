/*
 * Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

#include "s2n_test.h"

#include <stdint.h>
#include <s2n.h>

#include "tls/extensions/s2n_key_share.h"

#include "testlib/s2n_testlib.h"
#include "utils/s2n_safety.h"

int main(int argc, char **argv)
{
    BEGIN_TEST();

    /* Test s2n_ecc_find_supported_curve_by_iana_id() */
    {
        EXPECT_NULL(s2n_ecc_find_supported_curve_by_iana_id(0)); /* Reserved */
        EXPECT_NOT_NULL(s2n_ecc_find_supported_curve_by_iana_id(TLS_EC_CURVE_SECP_256_R1));
        EXPECT_NOT_NULL(s2n_ecc_find_supported_curve_by_iana_id(TLS_EC_CURVE_SECP_384_R1));

        EXPECT_NULL(s2n_ecc_find_supported_curve_by_iana_id(25)); /* secp521r1 */
        EXPECT_NULL(s2n_ecc_find_supported_curve_by_iana_id(29)); /* x25519 */
        EXPECT_NULL(s2n_ecc_find_supported_curve_by_iana_id(65023)); /* Unassigned */

        for (int i = 0; i < S2N_ECC_SUPPORTED_CURVES_COUNT; i++) {
            const struct s2n_ecc_named_curve *match_curve, *expected_curve;

            EXPECT_NOT_NULL(match_curve = &s2n_ecc_supported_curves[i]);
            EXPECT_NOT_NULL(expected_curve = s2n_ecc_find_supported_curve_by_iana_id(match_curve->iana_id));

            EXPECT_EQUAL(match_curve, expected_curve);
        }
    }

    END_TEST();
    return 0;
}
