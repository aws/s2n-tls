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

#include "s2n_test.h"

#include <stdint.h>

#include "tls/s2n_alerts.h"
#include "tls/s2n_config.h"
#include "tls/s2n_connection.h"
#include "tls/s2n_tls13.h"
#include "tls/extensions/s2n_client_key_share.h"
#include "tls/extensions/s2n_key_share.h"
#include "tls/extensions/s2n_client_psk_exchange_modes.h"

#include "testlib/s2n_testlib.h"
#include "stuffer/s2n_stuffer.h"
#include "utils/s2n_safety.h"


int main(int argc, char **argv)
{
    BEGIN_TEST();
    EXPECT_SUCCESS(s2n_enable_tls13());

    struct s2n_psk_identity psk_identity_vec[] = {
        { .identity = "test_psk_1", .obfuscated_ticket_age = 0, .hash_algorithm = S2N_HASH_SHA256 },
        { .identity = "test_psk_2", .obfuscated_ticket_age = 0, .hash_algorithm = S2N_HASH_SHA384 },
    };

    uint16_t psk_identity_vlen = sizeof(psk_identity_vec) / sizeof(psk_identity_vec[0]);

    /* Test s2n_client_psk_exchange_modes_extension.should_send */
    {
        /* Test that s2n_extension_should_send_if_psk_connection sends PSK key exchange mode only if PSK Identities are set by the client */
        {
            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));

            EXPECT_SUCCESS(s2n_connection_set_client_psk_identities(conn, psk_identity_vec, psk_identity_vlen));
            EXPECT_TRUE(s2n_client_psk_exchange_modes_extension.should_send(conn));

            EXPECT_SUCCESS(s2n_connection_free(conn));
        }
         /* Test that s2n_extension_should_send_if_psk_connection fails when PSK Identities are not set by the client */
        {
            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));

            EXPECT_FALSE(s2n_client_psk_exchange_modes_extension.should_send(conn));

            EXPECT_SUCCESS(s2n_connection_free(conn));
        }
        /* Test that s2n_extension_should_send_if_psk_connection fails when PSK Identities list is greater than S2N_PSK_VECTOR_MAX_SIZE */
        {
            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));

            EXPECT_SUCCESS(s2n_connection_set_client_psk_identities(conn, psk_identity_vec, psk_identity_vlen));
            conn->initial.client_psk_config.psk_vec_len = S2N_PSK_VECTOR_MAX_SIZE + 1;
            EXPECT_FALSE(s2n_client_psk_exchange_modes_extension.should_send(conn));

            EXPECT_SUCCESS(s2n_connection_free(conn));
        }
    }
    /* Test s2n_client_psk_exchange_modes_extension.send */
    {
        /* Test that s2n_client_psk_exchange_modes_extension.send sends PSK key exchange mode psk_dhe_ke */
        {
            struct s2n_stuffer psk_exchange_mode_extension;
            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&psk_exchange_mode_extension, 0));

            EXPECT_SUCCESS(s2n_client_psk_exchange_modes_extension.send(conn, &psk_exchange_mode_extension));

            uint8_t psk_mode = 0;
            EXPECT_SUCCESS(s2n_stuffer_read_uint8(&psk_exchange_mode_extension, &psk_mode));
            EXPECT_EQUAL(psk_mode, S2N_PSK_DHE_KE);

            EXPECT_SUCCESS(s2n_stuffer_free(&psk_exchange_mode_extension));
            EXPECT_SUCCESS(s2n_connection_free(conn));
        }
    }
    /* TODO: Test that server and client sends the key share extension if PSK exchange mode psk_dhe_ke is used */

    END_TEST();
    return 0;
}
