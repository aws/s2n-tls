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

#define ECDHE_PARAMS_LEGACY_FORM 4

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
        /* Test failure case for generate ephemeral key  when the negotiated curve is not set */
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
    {
        /* Test s2n_ecc_evp_write_params_point for all supported curves */
        for (int i = 0; i < s2n_ecc_evp_supported_curves_list_len; i++) {
            struct s2n_ecc_evp_params test_params = {0};
            struct s2n_stuffer wire;
            uint8_t legacy_form;

            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&wire, 0));

            /* Server generates a key for a given curve */
            test_params.negotiated_curve = s2n_ecc_evp_supported_curves_list[i];
            EXPECT_SUCCESS(s2n_ecc_evp_generate_ephemeral_key(&test_params));
            EXPECT_SUCCESS(s2n_ecc_evp_write_params_point(&test_params, &wire));

            /* Verify output is of the right length */
            uint32_t avail = s2n_stuffer_data_available(&wire);
            EXPECT_EQUAL(avail, s2n_ecc_evp_supported_curves_list[i]->share_size);

            /* Verify output starts with the known legacy form for curves secp256r1
             * and secp384r1*/
            if (s2n_ecc_evp_supported_curves_list[i]->iana_id == TLS_EC_CURVE_SECP_256_R1 ||
                s2n_ecc_evp_supported_curves_list[i]->iana_id == TLS_EC_CURVE_SECP_384_R1) {
                EXPECT_SUCCESS(s2n_stuffer_read_uint8(&wire, &legacy_form));
                EXPECT_EQUAL(legacy_form, ECDHE_PARAMS_LEGACY_FORM);
            }

            /* Clean up */
            EXPECT_SUCCESS(s2n_ecc_evp_params_free(&test_params));
            EXPECT_SUCCESS(s2n_stuffer_free(&wire));
        }
    }
    {
        /* TEST s2n_ecc_evp_read_params_point for all supported curves */
        for (int i = 0; i < s2n_ecc_evp_supported_curves_list_len; i++) {
            struct s2n_ecc_evp_params write_params = {0};
            struct s2n_blob point_blob;
            struct s2n_stuffer wire;

            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&wire, 0));

            /* Server generates a key for a given curve */
            write_params.negotiated_curve = s2n_ecc_evp_supported_curves_list[i];
            EXPECT_SUCCESS(s2n_ecc_evp_generate_ephemeral_key(&write_params));
            EXPECT_SUCCESS(s2n_ecc_evp_write_params_point(&write_params, &wire));

            /* Read point back in */
            EXPECT_SUCCESS(
                s2n_ecc_evp_read_params_point(&wire, s2n_ecc_evp_supported_curves_list[i]->share_size, &point_blob));

            /* Check that the blob looks generally correct. */
            EXPECT_EQUAL(point_blob.size, s2n_ecc_evp_supported_curves_list[i]->share_size);
            EXPECT_NOT_NULL(point_blob.data);

            EXPECT_SUCCESS(s2n_ecc_evp_params_free(&write_params));
            EXPECT_SUCCESS(s2n_stuffer_free(&wire));
        }
    }
    {
        /* TEST s2n_ecc_evp_parse_params_point for all supported curves */
        for (int i = 0; i < s2n_ecc_evp_supported_curves_list_len; i++) {
            struct s2n_ecc_evp_params write_params = {0};
            struct s2n_ecc_evp_params read_params = {0};
            struct s2n_blob point_blob;
            struct s2n_stuffer wire;

            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&wire, 0));

            write_params.negotiated_curve = s2n_ecc_evp_supported_curves_list[i];
            read_params.negotiated_curve = s2n_ecc_evp_supported_curves_list[i];

            /* Server generates a key for a given curve */
            EXPECT_SUCCESS(s2n_ecc_evp_generate_ephemeral_key(&write_params));
            EXPECT_SUCCESS(s2n_ecc_evp_write_params_point(&write_params, &wire));

            /* Read point back in */
            EXPECT_SUCCESS(
                s2n_ecc_evp_read_params_point(&wire, s2n_ecc_evp_supported_curves_list[i]->share_size, &point_blob));
            EXPECT_SUCCESS(s2n_ecc_evp_parse_params_point(&point_blob, &read_params));
            /* Check that the point we read is the same we wrote */
            EXPECT_TRUE(EVP_PKEY_cmp(write_params.evp_pkey, read_params.evp_pkey));

            /* Clean up */
            EXPECT_SUCCESS(s2n_ecc_evp_params_free(&write_params));
            EXPECT_SUCCESS(s2n_ecc_evp_params_free(&read_params));
            EXPECT_SUCCESS(s2n_stuffer_free(&wire));
        }
    }
    {
        /* Test read/write/parse params for all supported curves */
        for (int i = 0; i < s2n_ecc_evp_supported_curves_list_len; i++) {
            struct s2n_ecc_evp_params write_params = {0};
            struct s2n_ecc_evp_params read_params = {0};
            struct s2n_stuffer wire;
            struct s2n_blob ecdh_params_sent, ecdh_params_received;

            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&wire, 1024));

            write_params.negotiated_curve = s2n_ecc_evp_supported_curves_list[i];
            read_params.negotiated_curve = s2n_ecc_evp_supported_curves_list[i];

            /* Server generates a key for a given curve */
            EXPECT_SUCCESS(s2n_ecc_evp_generate_ephemeral_key(&write_params));

             /* Write params points to wire */
            EXPECT_SUCCESS(s2n_ecc_evp_write_params(&write_params, &wire, &ecdh_params_sent));
            struct s2n_ecdhe_raw_server_params ecdhe_data = {0};

             /* Read params points from the wire */
            EXPECT_SUCCESS(s2n_ecc_evp_read_params(&wire, &ecdh_params_received, &ecdhe_data));
            EXPECT_SUCCESS(s2n_ecc_evp_parse_params(&ecdhe_data, &read_params));

            /* Check that the point we read is the same we wrote */
            EXPECT_TRUE(EVP_PKEY_cmp(write_params.evp_pkey, read_params.evp_pkey));

            /* Clean up */ 
            EXPECT_SUCCESS(s2n_stuffer_free(&wire));
            EXPECT_SUCCESS(s2n_ecc_evp_params_free(&write_params));
            EXPECT_SUCCESS(s2n_ecc_evp_params_free(&read_params));
        }
    }
    {
        /* Test generate/read/write/parse and compute shared secrets for all supported curves */
        for (int i = 0; i < s2n_ecc_evp_supported_curves_list_len; i++) {
            struct s2n_ecc_evp_params server_params = {0};
            struct s2n_ecc_evp_params read_params = {0};
            struct s2n_ecc_evp_params client_params = {0}; 
            struct s2n_stuffer wire;
            struct s2n_blob ecdh_params_sent, ecdh_params_received;
            struct s2n_blob server_shared_secret, client_shared_secret;

            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&wire, 1024));

            server_params.negotiated_curve = s2n_ecc_evp_supported_curves_list[i];
            read_params.negotiated_curve = s2n_ecc_evp_supported_curves_list[i];

            /* Server generates a key for a given curve */
            EXPECT_SUCCESS(s2n_ecc_evp_generate_ephemeral_key(&server_params));

            /* Server sends the public */
            EXPECT_SUCCESS(s2n_ecc_evp_write_params(&server_params, &wire, &ecdh_params_sent));

            /* Client reads the public */
            struct s2n_ecdhe_raw_server_params ecdhe_data = {0};
            EXPECT_SUCCESS(s2n_ecc_evp_read_params(&wire, &ecdh_params_received, &ecdhe_data));
            EXPECT_SUCCESS(s2n_ecc_evp_parse_params(&ecdhe_data, &read_params));

            /* Verify if the client correctly read the server public */
            EXPECT_TRUE(EVP_PKEY_cmp(server_params.evp_pkey, read_params.evp_pkey));

             /* Client generates its key for the given curve */
            client_params.negotiated_curve =s2n_ecc_evp_supported_curves_list[i];
            EXPECT_SUCCESS(s2n_ecc_evp_generate_ephemeral_key(&client_params));
        
            /* Compute shared secret for the server */
            EXPECT_SUCCESS(
                s2n_ecc_evp_compute_shared_secret_from_params(&server_params, &client_params, &server_shared_secret));
            
            /* Compute shared secret for the client */
            EXPECT_SUCCESS(
                s2n_ecc_evp_compute_shared_secret_from_params(&client_params, &read_params, &client_shared_secret));

             /* Verify that shared is the same for the client and the server */
            EXPECT_EQUAL(client_shared_secret.size, server_shared_secret.size);
            EXPECT_BYTEARRAY_EQUAL(client_shared_secret.data, server_shared_secret.data, client_shared_secret.size);

            /* Clean up */
            EXPECT_SUCCESS(s2n_stuffer_free(&wire));
            EXPECT_SUCCESS(s2n_free(&server_shared_secret));
            EXPECT_SUCCESS(s2n_free(&client_shared_secret)); 
            EXPECT_SUCCESS(s2n_ecc_evp_params_free(&server_params));
            EXPECT_SUCCESS(s2n_ecc_evp_params_free(&read_params));
            EXPECT_SUCCESS(s2n_ecc_evp_params_free(&client_params));
        }
    }
    {
        /* Test generate->write->read->compute_shared with all supported curves */
    for (int i = 0; i < s2n_ecc_evp_supported_curves_list_len; i++) {
            struct s2n_ecc_evp_params server_params = {0}, client_params = {0};
            struct s2n_stuffer wire;
            struct s2n_blob server_shared, client_shared, ecdh_params_sent, ecdh_params_received;

            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&wire, 1024));

            /* Server generates a key for a given curve */
            server_params.negotiated_curve = s2n_ecc_evp_supported_curves_list[i];
            EXPECT_SUCCESS(s2n_ecc_evp_generate_ephemeral_key(&server_params));
            /* Server sends the public */
            EXPECT_SUCCESS(s2n_ecc_evp_write_params(&server_params, &wire, &ecdh_params_sent));
            /* Client reads the public */
            struct s2n_ecdhe_raw_server_params ecdhe_data = {0};
            EXPECT_SUCCESS(s2n_ecc_evp_read_params(&wire, &ecdh_params_received, &ecdhe_data));
            EXPECT_SUCCESS(s2n_ecc_evp_parse_params(&ecdhe_data, &client_params));

            /* The client got the curve */
            EXPECT_EQUAL(client_params.negotiated_curve, server_params.negotiated_curve);

            /* Client sends its public */
            EXPECT_SUCCESS(s2n_ecc_evp_compute_shared_secret_as_client(&client_params, &wire, &client_shared));
            /* Server receives it */
            EXPECT_SUCCESS(s2n_ecc_evp_compute_shared_secret_as_server(&server_params, &wire, &server_shared));
            /* Shared is the same for the client and the server */
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
