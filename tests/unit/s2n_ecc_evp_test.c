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

#include <s2n.h>

#include "crypto/s2n_ecc_evp.h"
#include "stuffer/s2n_stuffer.h"
#include "testlib/s2n_testlib.h"
#include "utils/s2n_mem.h"

int main(int argc, char **argv) {
    BEGIN_TEST();
    {
        /* Test generate ephemeral keys for all supported curves */
        for (int i = 1; i < S2N_ECC_EVP_SUPPORTED_CURVES_COUNT; i++) {
            struct s2n_ecc_evp_params evp_params;
            /* Server generates a key */
            EXPECT_FAILURE(s2n_ecc_evp_generate_ephemeral_key(&evp_params));
            evp_params.negotiated_curve = s2n_ecc_evp_supported_curves[i];
            EXPECT_SUCCESS(s2n_ecc_evp_generate_ephemeral_key(&evp_params));
            EXPECT_SUCCESS(s2n_ecc_evp_params_free(&evp_params));
        }
    }
    {
        /* Test generate ephemeral key and compute shared key for all supported curves */
        for (int i = 0; i < S2N_ECC_EVP_SUPPORTED_CURVES_COUNT; i++) {
            struct s2n_ecc_evp_params server_params, client_params;
            struct s2n_blob server_shared, client_shared;
            struct s2n_stuffer wire;
            server_params.negotiated_curve = s2n_ecc_evp_supported_curves[i];

            /* Server generates a key */
            EXPECT_SUCCESS(s2n_ecc_evp_generate_ephemeral_key(&server_params));
            client_params.negotiated_curve = s2n_ecc_evp_supported_curves[i];
            EXPECT_SUCCESS(s2n_ecc_evp_generate_ephemeral_key(&client_params));

            /* Compute shared secret for server*/
            EXPECT_SUCCESS(
                s2n_ecc_evp_compute_shared_secret_from_params(&server_params, &client_params, &server_shared));

            /* Compute shared secret for client*/
            EXPECT_SUCCESS(
                s2n_ecc_evp_compute_shared_secret_from_params(&client_params, &server_params, &client_shared));

            /* Check if the shared secret computed is the same for the client
             * and the server */
            EXPECT_EQUAL(client_shared.size, server_shared.size);
            EXPECT_BYTEARRAY_EQUAL(client_shared.data, server_shared.data, client_shared.size);

            /* Clean up */
            EXPECT_SUCCESS(s2n_stuffer_free(&wire));
            EXPECT_SUCCESS(s2n_free(&server_shared));
            EXPECT_SUCCESS(s2n_free(&client_shared));
            EXPECT_SUCCESS(s2n_ecc_evp_params_free(&server_params));
            EXPECT_SUCCESS(s2n_ecc_evp_params_free(&client_params));
        }
    }
    {
        /* Test failure case for computing shared key for all supported curves */
        for (int i = 1; i < S2N_ECC_EVP_SUPPORTED_CURVES_COUNT; i++) {
            struct s2n_ecc_evp_params server_params, client_params;
            struct s2n_blob server_shared, client_shared;
            struct s2n_stuffer wire;
            server_params.negotiated_curve = s2n_ecc_evp_supported_curves[i];

            /* Server generates a key */
            EXPECT_SUCCESS(s2n_ecc_evp_generate_ephemeral_key(&server_params));
            client_params.negotiated_curve = s2n_ecc_evp_supported_curves[0];
            EXPECT_SUCCESS(s2n_ecc_evp_generate_ephemeral_key(&client_params));

            /* Compute shared secret for server*/
            EXPECT_FAILURE(
                s2n_ecc_evp_compute_shared_secret_from_params(&server_params, &client_params, &server_shared));

            /* Compute shared secret for client*/
            EXPECT_FAILURE(
                s2n_ecc_evp_compute_shared_secret_from_params(&client_params, &server_params, &client_shared));

            /* Clean up */
            EXPECT_SUCCESS(s2n_stuffer_free(&wire));
            EXPECT_SUCCESS(s2n_free(&server_shared));
            EXPECT_SUCCESS(s2n_free(&client_shared));
            EXPECT_SUCCESS(s2n_ecc_evp_params_free(&server_params));
            EXPECT_SUCCESS(s2n_ecc_evp_params_free(&client_params));
        }
    }

    END_TEST();
}
