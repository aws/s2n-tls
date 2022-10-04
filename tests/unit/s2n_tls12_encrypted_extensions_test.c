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
#include "testlib/s2n_testlib.h"

#include "tls/s2n_tls.h"
#include "tls/extensions/s2n_npn.h"

#include "stuffer/s2n_stuffer.h"
#include "utils/s2n_safety.h"

int main(int argc, char **argv)
{
    BEGIN_TEST();

    /* Test s2n_tls12_encrypted_extensions_send */
    {
        /* Safety checks */
        EXPECT_FAILURE(s2n_tls12_encrypted_extensions_send(NULL));

        /* Should fail for >= TLS1.3 */
        {
            DEFER_CLEANUP(struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT), s2n_connection_ptr_free);
            EXPECT_NOT_NULL(client_conn);

            EXPECT_SUCCESS(s2n_connection_allow_all_response_extensions(client_conn));

            /* Fails for TLS1.3 */
            client_conn->actual_protocol_version = S2N_TLS13;
            EXPECT_FAILURE_WITH_ERRNO(s2n_tls12_encrypted_extensions_send(client_conn), S2N_ERR_BAD_MESSAGE);

            /* Succeeds for TLS1.2 */
            client_conn->actual_protocol_version = S2N_TLS12;
            EXPECT_SUCCESS(s2n_tls12_encrypted_extensions_send(client_conn));
        }

        /* Sends the npn extension */
        {
            DEFER_CLEANUP(struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT), s2n_connection_ptr_free);
            EXPECT_NOT_NULL(client_conn);
            EXPECT_SUCCESS(s2n_connection_allow_all_response_extensions(client_conn));
            client_conn->actual_protocol_version = S2N_TLS12;

            struct s2n_stuffer *stuffer = &client_conn->handshake.io;

            char protocol[] = { "http/1.1" };
            uint8_t protocol_len = strlen(protocol);
            EXPECT_MEMCPY_SUCCESS(client_conn->application_protocol, protocol, protocol_len + 1);

            EXPECT_SUCCESS(s2n_tls12_encrypted_extensions_send(client_conn));

            uint16_t extension_list_size = 0;
            EXPECT_SUCCESS(s2n_stuffer_read_uint16(stuffer, &extension_list_size));
            EXPECT_NOT_EQUAL(extension_list_size, 0);
            EXPECT_EQUAL(s2n_stuffer_data_available(stuffer), extension_list_size);

            uint16_t extension_type = 0;
            EXPECT_SUCCESS(s2n_stuffer_read_uint16(stuffer, &extension_type));
            EXPECT_EQUAL(extension_type, s2n_npn_encrypted_extension.iana_value);
        }
    }

    /* Test s2n_tls12_encrypted_extensions_recv */
    {
        /* Safety checks */
        EXPECT_FAILURE(s2n_tls12_encrypted_extensions_recv(NULL));

        /* Should fail for >=TLS1.3 */
        {
            DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER), s2n_connection_ptr_free);
            EXPECT_NOT_NULL(server_conn);

            /* Fails for TLS1.3 */
            server_conn->actual_protocol_version = S2N_TLS13;
            EXPECT_FAILURE_WITH_ERRNO(s2n_tls12_encrypted_extensions_recv(server_conn), S2N_ERR_BAD_MESSAGE);

            /* Succeeds for TLS1.2 */
            server_conn->actual_protocol_version = S2N_TLS12;
            EXPECT_SUCCESS(s2n_tls12_encrypted_extensions_recv(server_conn));
        }

        /* Should parse an empty list */
        {
            DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER), s2n_connection_ptr_free);
            EXPECT_NOT_NULL(server_conn);
            server_conn->actual_protocol_version = S2N_TLS12;

            struct s2n_stuffer *stuffer = &server_conn->handshake.io;

            /* Parse no data */
            EXPECT_SUCCESS(s2n_tls12_encrypted_extensions_recv(server_conn));
            EXPECT_EQUAL(s2n_stuffer_data_available(stuffer), 0);

            /* Parse explicitly empty list */
            EXPECT_SUCCESS(s2n_extension_list_send(S2N_EXTENSION_LIST_EMPTY, server_conn, stuffer));
            EXPECT_SUCCESS(s2n_tls12_encrypted_extensions_recv(server_conn));
            EXPECT_EQUAL(s2n_stuffer_data_available(stuffer), 0);
        }

        /* Should parse s2n_tls12_encrypted_extensions_send */
        {
            DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER), s2n_connection_ptr_free);
            EXPECT_NOT_NULL(server_conn);
            DEFER_CLEANUP(struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT), s2n_connection_ptr_free);
            EXPECT_NOT_NULL(client_conn);
            EXPECT_SUCCESS(s2n_connection_allow_all_response_extensions(client_conn));
            EXPECT_SUCCESS(s2n_connection_allow_all_response_extensions(server_conn));

            server_conn->actual_protocol_version = S2N_TLS12;
            client_conn->actual_protocol_version = S2N_TLS12;
            
            char protocol[] = { "http/1.1" };
            uint8_t protocol_len = strlen(protocol);
            EXPECT_MEMCPY_SUCCESS(client_conn->application_protocol, protocol, protocol_len + 1);

            struct s2n_stuffer *stuffer = &client_conn->handshake.io;

            EXPECT_SUCCESS(s2n_tls12_encrypted_extensions_send(client_conn));
            EXPECT_SUCCESS(s2n_stuffer_copy(stuffer, &server_conn->handshake.io, s2n_stuffer_data_available(stuffer)));
            EXPECT_SUCCESS(s2n_tls12_encrypted_extensions_recv(server_conn));
            EXPECT_EQUAL(s2n_stuffer_data_available(&server_conn->handshake.io), 0);

            EXPECT_BYTEARRAY_EQUAL(client_conn->application_protocol, server_conn->application_protocol, protocol_len);
        }

        /* Ignores unexpected extension */
        {
            DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER), s2n_connection_ptr_free);
            EXPECT_NOT_NULL(server_conn);
            server_conn->actual_protocol_version = S2N_TLS12;

            struct s2n_stuffer *stuffer = &server_conn->handshake.io;

            /* Setup connection to send a max early data extension */
            EXPECT_SUCCESS(s2n_connection_set_server_max_early_data_size(server_conn, 100));
            EXPECT_SUCCESS(s2n_extension_list_send(S2N_EXTENSION_LIST_NST, server_conn, stuffer));

            /* Set early data size to a different arbitrary size so that we can test whether or not it changes */
            uint32_t arbitrary_max_early_data = 300;
            EXPECT_SUCCESS(s2n_connection_set_server_max_early_data_size(server_conn, arbitrary_max_early_data));
            EXPECT_SUCCESS(s2n_tls12_encrypted_extensions_recv(server_conn));
            uint32_t max_early_data = 0;
            EXPECT_OK(s2n_early_data_get_server_max_size(server_conn, &max_early_data));

            /* Value is unchanged because extension was ignored */
            EXPECT_EQUAL(max_early_data, arbitrary_max_early_data);
        }
    }
    END_TEST();
}
