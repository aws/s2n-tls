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
#include "utils/s2n_mem.h"
#include "testlib/s2n_testlib.h"
#include "stuffer/s2n_stuffer.h"

int main(int argc, char **argv)
{
    BEGIN_TEST();

    /* Test s2n_ecc_evp_write_params_point for all supported curves */
    {
        for (int i = 0; i < S2N_ECC_EVP_SUPPORTED_CURVES_COUNT; i++)
        {
            struct s2n_ecc_evp_params test_params;
            struct s2n_stuffer wire;
            uint8_t legacy_form;

            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&wire, 1024));

            test_params.negotiated_curve = &s2n_ecc_evp_supported_curves[i];

            /* Server generates a key for a given curve */
            EXPECT_SUCCESS(s2n_ecc_evp_generate_ephemeral_key(&test_params));
            EXPECT_SUCCESS(s2n_ecc_evp_write_params_point(&test_params, &wire));

            /* Verify output is of the right length */
            uint32_t avail = s2n_stuffer_data_available(&wire);
            EXPECT_EQUAL(avail, s2n_ecc_evp_supported_curves[i].share_size);

            /* Verify output starts with the known legacy form for curves secp256r1 and secp384r1*/
            if (s2n_ecc_evp_supported_curves[i].iana_id == TLS_EC_CURVE_SECP_256_R1 ||
                s2n_ecc_evp_supported_curves[i].iana_id == TLS_EC_CURVE_SECP_384_R1)
            {
                EXPECT_SUCCESS(s2n_stuffer_read_uint8(&wire, &legacy_form));
                EXPECT_EQUAL(legacy_form, 4);
            }

            EXPECT_SUCCESS(s2n_ecc_evp_params_free(&test_params));
            EXPECT_SUCCESS(s2n_stuffer_free(&wire));
        }
    }

    /* TEST s2n_ecc_evp_read_params_point for all supported curves */
    {
        for (int i = 0; i < S2N_ECC_EVP_SUPPORTED_CURVES_COUNT; i++)
        {
            struct s2n_ecc_evp_params write_params;
            struct s2n_blob point_blob;
            struct s2n_stuffer wire;

            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&wire, 1024));

            write_params.negotiated_curve = &s2n_ecc_evp_supported_curves[i];

            /* Server generates a key for a given curve */
            EXPECT_SUCCESS(s2n_ecc_evp_generate_ephemeral_key(&write_params));
            EXPECT_SUCCESS(s2n_ecc_evp_write_params_point(&write_params, &wire));

            /* Read point back in */
            EXPECT_SUCCESS(s2n_ecc_evp_read_params_point(&wire, s2n_ecc_evp_supported_curves[i].share_size, &point_blob));

            /* Check that the blob looks generally correct. */
            EXPECT_EQUAL(point_blob.size, s2n_ecc_evp_supported_curves[i].share_size);
            EXPECT_NOT_NULL(point_blob.data);

            EXPECT_SUCCESS(s2n_ecc_evp_params_free(&write_params));
            EXPECT_SUCCESS(s2n_stuffer_free(&wire));
        }
    }

    /* TEST s2n_ecc_parse_ecc_params_point for all supported curves */
    {
        for (int i = 0; i < S2N_ECC_EVP_SUPPORTED_CURVES_COUNT; i++)
        {
            struct s2n_ecc_evp_params write_params, read_params;
            struct s2n_blob point_blob;
            struct s2n_stuffer wire;

            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&wire, 1024));

            write_params.negotiated_curve = &s2n_ecc_evp_supported_curves[i];
            read_params.negotiated_curve = &s2n_ecc_evp_supported_curves[i];

            /* Server generates a key for a given curve */
            EXPECT_SUCCESS(s2n_ecc_evp_generate_ephemeral_key(&write_params));
            EXPECT_SUCCESS(s2n_ecc_evp_write_params_point(&write_params, &wire));

            /* Read point back in */
            EXPECT_SUCCESS(s2n_ecc_evp_read_params_point(&wire, s2n_ecc_evp_supported_curves[i].share_size, &point_blob));
            EXPECT_SUCCESS(s2n_ecc_evp_generate_copy_params(&write_params, &read_params));
            EXPECT_SUCCESS(s2n_ecc_evp_parse_params_point(&point_blob, &read_params));

            /* Check that the point we read is the same we wrote */
            EXPECT_TRUE(1 == EVP_PKEY_cmp(write_params.evp_pkey, read_params.evp_pkey));

            EXPECT_SUCCESS(s2n_ecc_evp_params_free(&write_params));
            EXPECT_SUCCESS(s2n_ecc_evp_params_free(&read_params));
            EXPECT_SUCCESS(s2n_stuffer_free(&wire));
        }
    }

    {
        for (int i = 0; i < S2N_ECC_EVP_SUPPORTED_CURVES_COUNT; i++)
        {
            struct s2n_ecc_evp_params ecc_evp_params;
            struct s2n_blob server_shared, client_shared;
            struct s2n_stuffer wire;
            ecc_evp_params.negotiated_curve = &s2n_ecc_evp_supported_curves[i];

            /* Server generates a key */
            EXPECT_SUCCESS(s2n_ecc_evp_generate_ephemeral_key(&ecc_evp_params));

            /* Client generates a key, computes its shared secret and sends the client public key */
            EXPECT_SUCCESS(s2n_ecc_evp_compute_shared_secret_as_client(&ecc_evp_params, &wire, &client_shared));

            /* Server receives the client public key and computes its shared secret */
            EXPECT_SUCCESS(s2n_ecc_evp_compute_shared_secret_as_server(&ecc_evp_params, &wire, &server_shared));

            /* Check if the shared secret computed is the same for the client and the server */
            EXPECT_EQUAL(client_shared.size, server_shared.size);
            EXPECT_BYTEARRAY_EQUAL(client_shared.data, server_shared.data, client_shared.size);

            /* Clean up */
            EXPECT_SUCCESS(s2n_stuffer_free(&wire));
            EXPECT_SUCCESS(s2n_free(&server_shared));
            EXPECT_SUCCESS(s2n_free(&client_shared));
            EXPECT_SUCCESS(s2n_ecc_evp_params_free(&ecc_evp_params));
        }
    }

    {
        for (int i = 0; i < S2N_ECC_EVP_SUPPORTED_CURVES_COUNT; i++)
        {
            struct s2n_ecc_evp_params server_params, client_params;
            struct s2n_blob server_shared, client_shared;
            struct s2n_stuffer wire;
            server_params.negotiated_curve = &s2n_ecc_evp_supported_curves[i];

            /* Server generates a key */
            EXPECT_SUCCESS(s2n_ecc_evp_generate_ephemeral_key(&server_params));
            client_params.negotiated_curve = &s2n_ecc_evp_supported_curves[i];
            EXPECT_SUCCESS(s2n_ecc_evp_generate_ephemeral_key(&client_params));

            /* Compute shared secret for server*/
            EXPECT_SUCCESS(s2n_ecc_evp_compute_shared_secret_from_params(&server_params, &client_params, &server_shared));

            /* Compute shared secret for client*/
            EXPECT_SUCCESS(s2n_ecc_evp_compute_shared_secret_from_params(&client_params, &server_params, &client_shared));

            /* Check if the shared secret computed is the same for the client and the server */
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

    END_TEST();
}
