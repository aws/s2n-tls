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

#include <stdint.h>

#include "crypto/s2n_ecc_evp.h"
#include "s2n_test.h"
#include "stuffer/s2n_stuffer.h"
#include "testlib/s2n_testlib.h"
#include "tls/extensions/s2n_key_share.h"
#include "tls/s2n_tls.h"
#include "utils/s2n_safety.h"

int main(int argc, char **argv)
{
    BEGIN_TEST();
    EXPECT_SUCCESS(s2n_disable_tls13_in_test());
    const struct s2n_ecc_named_curve *test_curve = s2n_all_supported_curves_list[0];

    /* Test s2n_ecdhe_parameters_send write with valid ecc params */
    {
        struct s2n_stuffer out = { 0 };

        struct s2n_ecc_evp_params ecc_evp_params;
        ecc_evp_params.negotiated_curve = test_curve;
        ecc_evp_params.evp_pkey = NULL;

        EXPECT_SUCCESS(s2n_stuffer_alloc(&out, test_curve->share_size + 4));
        EXPECT_SUCCESS(s2n_ecdhe_parameters_send(&ecc_evp_params, &out));
        S2N_STUFFER_READ_EXPECT_EQUAL(&out, test_curve->iana_id, uint16);
        S2N_STUFFER_READ_EXPECT_EQUAL(&out, test_curve->share_size, uint16);
        EXPECT_EQUAL(s2n_stuffer_data_available(&out), test_curve->share_size);

        EXPECT_SUCCESS(s2n_ecc_evp_params_free(&ecc_evp_params));
        EXPECT_SUCCESS(s2n_stuffer_free(&out));
    };

    /* Test s2n_ecdhe_parameters_send failure with bad ecc params */
    {
        struct s2n_stuffer out = { 0 };

        struct s2n_ecc_evp_params ecc_evp_params;
        const struct s2n_ecc_named_curve bad_curve = {
            .iana_id = 12345,
            .libcrypto_nid = 0,
            .name = test_curve->name,
            .share_size = test_curve->share_size
        };

        ecc_evp_params.negotiated_curve = &bad_curve;
        ecc_evp_params.evp_pkey = NULL;

        EXPECT_SUCCESS(s2n_stuffer_alloc(&out, bad_curve.share_size + 4));
        /* generating an ECDHE key should fail */
        EXPECT_FAILURE(s2n_ecdhe_parameters_send(&ecc_evp_params, &out));

        EXPECT_SUCCESS(s2n_ecc_evp_params_free(&ecc_evp_params));
        EXPECT_SUCCESS(s2n_stuffer_free(&out));
    };

    END_TEST();
}
