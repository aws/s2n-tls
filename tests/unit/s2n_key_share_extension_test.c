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

#include "tls/s2n_tls.h"
#include "tls/extensions/s2n_key_share.h"

#include "testlib/s2n_testlib.h"
#include "stuffer/s2n_stuffer.h"
#include "utils/s2n_safety.h"

int main(int argc, char **argv)
{
    BEGIN_TEST();

    /* Test s2n_ecdhe_parameters_send write with valid ecc params */
    {
        struct s2n_stuffer out;

        struct s2n_ecc_evp_params ecc_evp_params;
        const struct s2n_ecc_named_curve *curve = s2n_ecc_evp_supported_curves_list[0];
        ecc_evp_params.negotiated_curve = curve;
        ecc_evp_params.evp_pkey = NULL;

        EXPECT_SUCCESS(s2n_stuffer_alloc(&out, curve->share_size + 4));
        EXPECT_SUCCESS(s2n_ecdhe_parameters_send(&ecc_evp_params, &out));
        S2N_STUFFER_READ_EXPECT_EQUAL(&out, curve->iana_id, uint16);
        S2N_STUFFER_READ_EXPECT_EQUAL(&out, curve->share_size, uint16);
        EXPECT_EQUAL(s2n_stuffer_data_available(&out), curve->share_size);

        EXPECT_SUCCESS(s2n_ecc_evp_params_free(&ecc_evp_params));
        EXPECT_SUCCESS(s2n_stuffer_free(&out));
    }

    /* Test s2n_ecdhe_parameters_send failure with bad ecc params */
    {
        struct s2n_stuffer out;

        struct s2n_ecc_evp_params ecc_evp_params;
        const struct s2n_ecc_named_curve *good_curve = s2n_ecc_evp_supported_curves_list[0];
        const struct s2n_ecc_named_curve curve = {
            .iana_id = 12345,
            .libcrypto_nid = 0,
            .name = good_curve->name,
            .share_size = good_curve->share_size
        };

        ecc_evp_params.negotiated_curve = &curve;
        ecc_evp_params.evp_pkey = NULL;

        EXPECT_SUCCESS(s2n_stuffer_alloc(&out, curve.share_size + 4));
        /* generating an ECDHE key should fail */
        EXPECT_FAILURE(s2n_ecdhe_parameters_send(&ecc_evp_params, &out));

        EXPECT_SUCCESS(s2n_ecc_evp_params_free(&ecc_evp_params));
        EXPECT_SUCCESS(s2n_stuffer_free(&out));
    }

    END_TEST();
}
