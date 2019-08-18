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

#include "tls/s2n_alerts.h"
#include "tls/s2n_config.h"
#include "tls/s2n_connection.h"
#include "tls/s2n_tls.h"
#include "tls/extensions/s2n_client_key_share.h"

#include "stuffer/s2n_stuffer.h"
#include "utils/s2n_safety.h"

int main(int argc, char **argv)
{
    BEGIN_TEST();

    struct s2n_connection *conn;

    /* Test that s2n_extensions_key_share_recv isn't implemented yet */
    {
        EXPECT_FAILURE_WITH_ERRNO(s2n_extensions_client_key_share_recv(NULL, NULL), S2N_ERR_UNIMPLEMENTED);
    }

    /* Test that s2n_extensions_key_share_size produces the expected constant result */
    {
        struct s2n_stuffer key_share_extension;
        EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));

        int key_share_size;
        EXPECT_SUCCESS(key_share_size = s2n_extensions_client_key_share_size(conn));

        /* should produce the same result if called twice */
        int key_share_size_again;
        EXPECT_SUCCESS(key_share_size_again = s2n_extensions_client_key_share_size(conn));
        EXPECT_EQUAL(key_share_size, key_share_size_again);

        /* should equal the size of the data written on send */
        EXPECT_SUCCESS(s2n_stuffer_alloc(&key_share_extension, key_share_size));
        EXPECT_SUCCESS(s2n_extensions_client_key_share_send(conn, &key_share_extension));
        EXPECT_EQUAL(key_share_size, s2n_stuffer_data_available(&key_share_extension));

        EXPECT_SUCCESS(s2n_stuffer_free(&key_share_extension));
        EXPECT_SUCCESS(s2n_connection_free(conn));
    }

    /* Test s2n_extensions_key_share_send */
    {
        /* Test that s2n_extensions_key_share_send initializes the client key share list */
        {
            struct s2n_stuffer key_share_extension;
            EXPECT_SUCCESS(s2n_stuffer_alloc(&key_share_extension, s2n_extensions_client_key_share_size(conn)));
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));

            EXPECT_SUCCESS(s2n_extensions_client_key_share_send(conn, &key_share_extension));

            for (int i = 0; i < S2N_ECC_SUPPORTED_CURVES_COUNT; i++) {
                struct s2n_ecc_params *ecc_params = &conn->secure.client_ecc_params[i];
                EXPECT_EQUAL(ecc_params->negotiated_curve, &s2n_ecc_supported_curves[i]);
                EXPECT_NOT_NULL(ecc_params->ec_key);
            }

            EXPECT_SUCCESS(s2n_stuffer_free(&key_share_extension));
            EXPECT_SUCCESS(s2n_connection_free(conn));
        }

        /* Test that s2n_extensions_key_share_send writes a well-formed list of key shares */
        {
            struct s2n_stuffer key_share_extension;
            EXPECT_SUCCESS(s2n_stuffer_alloc(&key_share_extension, s2n_extensions_client_key_share_size(conn)));
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));

            EXPECT_SUCCESS(s2n_extensions_client_key_share_send(conn, &key_share_extension));

            /* should start with correct extension type */
            uint16_t extension_type;
            EXPECT_SUCCESS(s2n_stuffer_read_uint16(&key_share_extension, &extension_type));
            EXPECT_EQUAL(extension_type, TLS_EXTENSION_KEY_SHARE);

            /* should start with correct extension size */
            uint16_t extension_size;
            EXPECT_SUCCESS(s2n_stuffer_read_uint16(&key_share_extension, &extension_size));
            uint16_t actual_extension_size = s2n_stuffer_data_available(&key_share_extension);
            EXPECT_EQUAL(extension_size, actual_extension_size);

            /* should have correct shares size */
            uint16_t key_shares_size;
            EXPECT_SUCCESS(s2n_stuffer_read_uint16(&key_share_extension, &key_shares_size));
            uint16_t actual_key_shares_size = s2n_stuffer_data_available(&key_share_extension);
            EXPECT_EQUAL(key_shares_size, actual_key_shares_size);

            /* should contain every supported curve, in order, with their sizes */
            for (int i = 0; i < S2N_ECC_SUPPORTED_CURVES_COUNT; i++) {
                uint16_t iana_value, share_size;
                EXPECT_SUCCESS(s2n_stuffer_read_uint16(&key_share_extension, &iana_value));
                EXPECT_EQUAL(iana_value, s2n_ecc_supported_curves[i].iana_id);
                EXPECT_SUCCESS(s2n_stuffer_read_uint16(&key_share_extension, &share_size));
                EXPECT_EQUAL(share_size, s2n_ecc_supported_curves[i].share_size);

                EXPECT_SUCCESS(s2n_stuffer_skip_read(&key_share_extension, share_size));
            }

            EXPECT_SUCCESS(s2n_stuffer_free(&key_share_extension));
            EXPECT_SUCCESS(s2n_connection_free(conn));
        }
    }

    END_TEST();
    return 0;
}
