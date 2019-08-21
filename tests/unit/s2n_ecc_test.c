/*
 * Copyright 2015 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

#include "crypto/s2n_ecc.h"
#include "utils/s2n_mem.h"

static int s2n_test_compare_ecc_keys(EC_KEY *key1, EC_KEY *key2)
{
    /* Both EC_cmp functions return 0 on equal, 1 on not equal, and -1 on error */

    if (EC_GROUP_cmp(EC_KEY_get0_group(key1), EC_KEY_get0_group(key2), NULL) != 0) {
        return 0;
    }

    if (EC_POINT_cmp(EC_KEY_get0_group(key1), EC_KEY_get0_public_key(key1), EC_KEY_get0_public_key(key2), NULL) != 0) {
        return 0;
    }

    return 1;
}

int main(int argc, char **argv)
{
    BEGIN_TEST();

    /* Test s2n_ecc_write_ecc_params_point for all supported curves */
    {
        for (int i = 0; i < S2N_ECC_SUPPORTED_CURVES_COUNT; i++) {
            struct s2n_ecc_params test_params;
            struct s2n_stuffer wire;
            uint8_t legacy_form;

            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&wire, 1024));

            test_params.negotiated_curve = &s2n_ecc_supported_curves[i];

            /* Server generates a key for a given curve */
            EXPECT_SUCCESS(s2n_ecc_generate_ephemeral_key(&test_params));
            EXPECT_SUCCESS(s2n_ecc_write_ecc_params_point(&test_params, &wire));

            /* Verify output is of the right length */
            EXPECT_EQUAL(s2n_stuffer_data_available(&wire), s2n_ecc_supported_curves[i].share_size);

            /* Verify output starts with the known legacy form */
            EXPECT_SUCCESS(s2n_stuffer_read_uint8(&wire, &legacy_form));
            EXPECT_EQUAL(legacy_form, 4);

            EXPECT_SUCCESS(s2n_ecc_params_free(&test_params));
            EXPECT_SUCCESS(s2n_stuffer_free(&wire));
        }
    }

    /* TEST s2n_ecc_read_ecc_params_point for all supported curves */
    {
        for (int i = 0; i < S2N_ECC_SUPPORTED_CURVES_COUNT; i++) {
            struct s2n_ecc_params write_params;
            struct s2n_blob point_blob;
            struct s2n_stuffer wire;

            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&wire, 1024));

            write_params.negotiated_curve = &s2n_ecc_supported_curves[i];

            /* Server generates a key for a given curve */
            EXPECT_SUCCESS(s2n_ecc_generate_ephemeral_key(&write_params));
            EXPECT_SUCCESS(s2n_ecc_write_ecc_params_point(&write_params, &wire));

            /* Read point back in */
            EXPECT_SUCCESS(s2n_ecc_read_ecc_params_point(&wire, &point_blob, s2n_ecc_supported_curves[i].share_size));

            /* Check that the blob looks generally correct. */
            EXPECT_EQUAL(point_blob.size, s2n_ecc_supported_curves[i].share_size);
            EXPECT_NOT_NULL(point_blob.data);

            EXPECT_SUCCESS(s2n_ecc_params_free(&write_params));
            EXPECT_SUCCESS(s2n_stuffer_free(&wire));
        }
    }

    /* TEST s2n_ecc_parse_ecc_params_point for all supported curves */
    {
        for (int i = 0; i < S2N_ECC_SUPPORTED_CURVES_COUNT; i++) {
            struct s2n_ecc_params write_params, read_params;
            struct s2n_blob point_blob;
            struct s2n_stuffer wire;

            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&wire, 1024));

            write_params.negotiated_curve = &s2n_ecc_supported_curves[i];
            read_params.negotiated_curve = &s2n_ecc_supported_curves[i];

            /* Server generates a key for a given curve */
            EXPECT_SUCCESS(s2n_ecc_generate_ephemeral_key(&write_params));
            EXPECT_SUCCESS(s2n_ecc_write_ecc_params_point(&write_params, &wire));

            /* Read point back in */
            EXPECT_SUCCESS(s2n_ecc_read_ecc_params_point(&wire, &point_blob, s2n_ecc_supported_curves[i].share_size));
            EXPECT_SUCCESS(s2n_ecc_parse_ecc_params_point(&read_params, &point_blob));

            /* Check that the point we read is the same we wrote */
            EXPECT_TRUE(s2n_test_compare_ecc_keys(write_params.ec_key, read_params.ec_key));

            EXPECT_SUCCESS(s2n_ecc_params_free(&write_params));
            EXPECT_SUCCESS(s2n_ecc_params_free(&read_params));
            EXPECT_SUCCESS(s2n_stuffer_free(&wire));
        }
    }

    /* Test generate->write->read->compute_shared with all supported curves */
    for (int i = 0; i < S2N_ECC_SUPPORTED_CURVES_COUNT; i++) {
        struct s2n_ecc_params server_params, client_params;
        struct s2n_stuffer wire;
        struct s2n_blob server_shared, client_shared, ecdh_params_sent, ecdh_params_received;

        EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&wire, 1024));

        /* Server generates a key for a given curve */
        server_params.negotiated_curve = &s2n_ecc_supported_curves[i];
        EXPECT_SUCCESS(s2n_ecc_generate_ephemeral_key(&server_params));
        /* Server sends the public */
        EXPECT_SUCCESS(s2n_ecc_write_ecc_params(&server_params, &wire, &ecdh_params_sent));
        /* Client reads the public */
        struct s2n_ecdhe_raw_server_params ecdhe_data = {0};
        EXPECT_SUCCESS(s2n_ecc_read_ecc_params(&wire, &ecdh_params_received, &ecdhe_data));
        EXPECT_SUCCESS(s2n_ecc_parse_ecc_params(&client_params, &ecdhe_data));

        /* The client got the curve */
        EXPECT_EQUAL(client_params.negotiated_curve, server_params.negotiated_curve);

        /* Client sends its public */
        EXPECT_SUCCESS(s2n_ecc_compute_shared_secret_as_client(&client_params, &wire, &client_shared));
        /* Server receives it */
        EXPECT_SUCCESS(s2n_ecc_compute_shared_secret_as_server(&server_params, &wire, &server_shared));
        /* Shared is the same for the client and the server */
        EXPECT_EQUAL(client_shared.size, server_shared.size);
        EXPECT_BYTEARRAY_EQUAL(client_shared.data, server_shared.data, client_shared.size);

        /* Clean up */
        EXPECT_SUCCESS(s2n_stuffer_free(&wire));
        EXPECT_SUCCESS(s2n_free(&server_shared));
        EXPECT_SUCCESS(s2n_free(&client_shared));
        EXPECT_SUCCESS(s2n_ecc_params_free(&server_params));
        EXPECT_SUCCESS(s2n_ecc_params_free(&client_params));
    }

    END_TEST();
}
