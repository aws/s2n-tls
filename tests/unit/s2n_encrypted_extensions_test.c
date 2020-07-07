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
#include "tls/s2n_tls13.h"

#include "tls/extensions/s2n_extension_type.h"
#include "tls/extensions/s2n_server_alpn.h"
#include "tls/extensions/s2n_server_max_fragment_length.h"
#include "tls/extensions/s2n_server_server_name.h"
#include "tls/extensions/s2n_server_supported_versions.h"

#include "error/s2n_errno.h"
#include "stuffer/s2n_stuffer.h"
#include "utils/s2n_safety.h"

int main(int argc, char **argv)
{
    BEGIN_TEST();

    EXPECT_SUCCESS(s2n_enable_tls13());

    /* Test s2n_encrypted_extensions_send */
    {
        /* Safety checks */
        EXPECT_FAILURE(s2n_encrypted_extensions_send(NULL));

        /* Should fail for pre-TLS1.3 */
        {
            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));
            EXPECT_SUCCESS(s2n_connection_allow_all_response_extensions(conn));

            /* Fails for TLS1.2 */
            conn->actual_protocol_version = S2N_TLS12;
            EXPECT_FAILURE_WITH_ERRNO(s2n_encrypted_extensions_send(conn), S2N_ERR_BAD_MESSAGE);

            /* Succeeds for TLS1.3 */
            conn->actual_protocol_version = S2N_TLS13;
            EXPECT_SUCCESS(s2n_encrypted_extensions_send(conn));

            EXPECT_SUCCESS(s2n_connection_free(conn));
        }

        /* Should send no extensions by default */
        {
            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));
            EXPECT_SUCCESS(s2n_connection_allow_all_response_extensions(conn));
            conn->actual_protocol_version = S2N_TLS13;

            struct s2n_stuffer *stuffer = &conn->handshake.io;

            EXPECT_SUCCESS(s2n_encrypted_extensions_send(conn));

            uint16_t extension_list_size;
            EXPECT_SUCCESS(s2n_stuffer_read_uint16(stuffer, &extension_list_size));
            EXPECT_EQUAL(extension_list_size, 0);
            EXPECT_EQUAL(s2n_stuffer_data_available(stuffer), 0);

            EXPECT_SUCCESS(s2n_connection_free(conn));
        }

        /* Should send a requested extension */
        {
            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));
            EXPECT_SUCCESS(s2n_connection_allow_all_response_extensions(conn));
            conn->actual_protocol_version = S2N_TLS13;

            struct s2n_stuffer *stuffer = &conn->handshake.io;

            conn->server_name_used = 1;
            EXPECT_SUCCESS(s2n_encrypted_extensions_send(conn));

            uint16_t extension_list_size;
            EXPECT_SUCCESS(s2n_stuffer_read_uint16(stuffer, &extension_list_size));
            EXPECT_NOT_EQUAL(extension_list_size, 0);
            EXPECT_EQUAL(s2n_stuffer_data_available(stuffer), extension_list_size);

            uint16_t extension_type;
            EXPECT_SUCCESS(s2n_stuffer_read_uint16(stuffer, &extension_type));
            EXPECT_EQUAL(extension_type, s2n_server_server_name_extension.iana_value);

            EXPECT_SUCCESS(s2n_connection_free(conn));
        }
    }

    /* Test s2n_encrypted_extensions_recv */
    {
        /* Safety checks */
        EXPECT_FAILURE(s2n_encrypted_extensions_recv(NULL));

        /* Should fail for pre-TLS1.3 */
        {
            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));
            EXPECT_SUCCESS(s2n_connection_allow_all_response_extensions(conn));

            /* Fails for TLS1.2 */
            conn->actual_protocol_version = S2N_TLS12;
            EXPECT_FAILURE_WITH_ERRNO(s2n_encrypted_extensions_recv(conn), S2N_ERR_BAD_MESSAGE);

            /* Succeeds for TLS1.3 */
            conn->actual_protocol_version = S2N_TLS13;
            EXPECT_SUCCESS(s2n_encrypted_extensions_recv(conn));

            EXPECT_SUCCESS(s2n_connection_free(conn));
        }

        /* Should parse an empty list */
        {
            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));
            EXPECT_SUCCESS(s2n_connection_allow_all_response_extensions(conn));
            conn->actual_protocol_version = S2N_TLS13;

            struct s2n_stuffer *stuffer = &conn->handshake.io;

            /* Parse no data */
            EXPECT_SUCCESS(s2n_encrypted_extensions_recv(conn));
            EXPECT_EQUAL(s2n_stuffer_data_available(stuffer), 0);

            /* Parse explicitly empty list */
            EXPECT_SUCCESS(s2n_extension_list_send(S2N_EXTENSION_LIST_EMPTY, conn, stuffer));
            EXPECT_SUCCESS(s2n_encrypted_extensions_recv(conn));
            EXPECT_EQUAL(s2n_stuffer_data_available(stuffer), 0);

            /* Parse empty result of default s2n_encrypted_extensions_send */
            EXPECT_SUCCESS(s2n_encrypted_extensions_send(conn));
            EXPECT_SUCCESS(s2n_encrypted_extensions_recv(conn));
            EXPECT_EQUAL(s2n_stuffer_data_available(stuffer), 0);

            EXPECT_SUCCESS(s2n_connection_free(conn));
        }

        /* Should parse a requested extension */
        {
            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));
            EXPECT_SUCCESS(s2n_connection_allow_all_response_extensions(conn));
            conn->actual_protocol_version = S2N_TLS13;

            struct s2n_stuffer *stuffer = &conn->handshake.io;

            conn->server_name_used = 1;
            EXPECT_SUCCESS(s2n_encrypted_extensions_send(conn));

            /* Reset server_name_used */
            conn->server_name_used = 0;

            EXPECT_SUCCESS(s2n_encrypted_extensions_recv(conn));
            EXPECT_EQUAL(s2n_stuffer_data_available(stuffer), 0);
            EXPECT_EQUAL(conn->server_name_used, 1);

            EXPECT_SUCCESS(s2n_connection_free(conn));
        }
    }

    END_TEST();
}
