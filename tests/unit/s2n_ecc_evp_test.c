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
        for (int i = 0; i < s2n_ecc_evp_supported_curves_list_len; i++) {
            struct s2n_ecc_evp_params evp_params = {0};
            /* Server generates a key */
            evp_params.negotiated_curve = s2n_ecc_evp_supported_curves_list[i];
            EXPECT_SUCCESS(s2n_ecc_evp_generate_ephemeral_key(&evp_params));
            EXPECT_SUCCESS(s2n_ecc_evp_params_free(&evp_params));
        }
    }
    {
        /* Test failure case for generate ephemeral key when the negotiated curve is not set */
        for (int i = 0; i < s2n_ecc_evp_supported_curves_list_len; i++) {
            struct s2n_ecc_evp_params evp_params = {0};
            /* Server generates a key */
            evp_params.negotiated_curve = NULL;
            EXPECT_FAILURE(s2n_ecc_evp_generate_ephemeral_key(&evp_params));
            EXPECT_SUCCESS(s2n_ecc_evp_params_free(&evp_params));
        }
    }
    {
        /* Test generate ephemeral key and compute shared key for all supported curves */
        for (int i = 0; i < s2n_ecc_evp_supported_curves_list_len; i++) {
            struct s2n_ecc_evp_params server_params = {0};
            struct s2n_ecc_evp_params client_params = {0};
            struct s2n_blob server_shared = {0};
            struct s2n_blob client_shared = {0};

            /* Server generates a key */
            server_params.negotiated_curve = s2n_ecc_evp_supported_curves_list[i];
            EXPECT_SUCCESS(s2n_ecc_evp_generate_ephemeral_key(&server_params));

            /* Client generates a key */
            client_params.negotiated_curve = s2n_ecc_evp_supported_curves_list[i];
            EXPECT_SUCCESS(s2n_ecc_evp_generate_ephemeral_key(&client_params));

            /* Compute shared secret for server */
            EXPECT_SUCCESS(
                s2n_ecc_evp_compute_shared_secret_from_params(&server_params, &client_params, &server_shared));

            /* Compute shared secret for client */
            EXPECT_SUCCESS(
                s2n_ecc_evp_compute_shared_secret_from_params(&client_params, &server_params, &client_shared));

            /* Check if the shared secret computed is the same for the client
             * and the server */
            EXPECT_EQUAL(client_shared.size, server_shared.size);
            EXPECT_BYTEARRAY_EQUAL(client_shared.data, server_shared.data, client_shared.size);

            /* Clean up */
            EXPECT_SUCCESS(s2n_free(&server_shared));
            EXPECT_SUCCESS(s2n_free(&client_shared));
            EXPECT_SUCCESS(s2n_ecc_evp_params_free(&server_params));
            EXPECT_SUCCESS(s2n_ecc_evp_params_free(&client_params));
        }
    }
    {
        /* Test failure case for computing shared key for all supported curves when the server
        and client curves donot match */
        for (int i = 0; i < s2n_ecc_evp_supported_curves_list_len; i++) {
            for (int j = 0; j < s2n_ecc_evp_supported_curves_list_len; j++) {
                    struct s2n_ecc_evp_params server_params = {0};
                    struct s2n_ecc_evp_params client_params = {0};
                    struct s2n_blob server_shared = {0};
                    struct s2n_blob client_shared = {0};
                    if (i == j) {
                        continue;
                    }

                    /* Server generates a key */
                    server_params.negotiated_curve = s2n_ecc_evp_supported_curves_list[j];

                    EXPECT_SUCCESS(s2n_ecc_evp_generate_ephemeral_key(&server_params));

                    /* Client generates a key */
                    client_params.negotiated_curve = s2n_ecc_evp_supported_curves_list[i];
                    EXPECT_SUCCESS(s2n_ecc_evp_generate_ephemeral_key(&client_params));

                    /* Compute shared secret for server */
                    EXPECT_FAILURE(
                        s2n_ecc_evp_compute_shared_secret_from_params(&server_params, &client_params, &server_shared));

                    /* Compute shared secret for client */
                    EXPECT_FAILURE(
                        s2n_ecc_evp_compute_shared_secret_from_params(&client_params, &server_params, &client_shared));

                    /* Clean up */
                    EXPECT_SUCCESS(s2n_ecc_evp_params_free(&server_params));
                    EXPECT_SUCCESS(s2n_ecc_evp_params_free(&client_params));
            }
        }
    }

    END_TEST();
}
