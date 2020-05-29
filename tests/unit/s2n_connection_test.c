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

#include "tls/s2n_connection.h"

#include "tls/extensions/s2n_extension_list.h"
#include "tls/extensions/s2n_client_server_name.h"
#include "tls/s2n_tls.h"

const uint8_t actual_version = 1, client_version = 2, server_version = 3;
static int s2n_set_test_protocol_versions(struct s2n_connection *conn)
{
    conn->actual_protocol_version = actual_version;
    conn->client_protocol_version = client_version;
    conn->server_protocol_version = server_version;
    return S2N_SUCCESS;
}

bool s2n_server_name_test_callback_flag = false;
static int s2n_server_name_test_callback(struct s2n_connection *conn, void *ctx)
{
    const char* expected_server_name = *(const char**) ctx;

    const char* actual_server_name = NULL;
    EXPECT_NOT_NULL(actual_server_name = s2n_get_server_name(conn));
    EXPECT_STRING_EQUAL(actual_server_name, expected_server_name);

    s2n_server_name_test_callback_flag = true;
    return S2N_SUCCESS;
}

int main(int argc, char **argv)
{
    BEGIN_TEST();

    /* s2n_get_server_name */
    {
        const char* test_server_name = "A server name";

        /* Safety check */
        EXPECT_NULL(s2n_get_server_name(NULL));

        /* Return NULL by default / for new connection */
        {
            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));

            EXPECT_NULL(s2n_get_server_name(conn));

            EXPECT_SUCCESS(s2n_connection_free(conn));
        }

        /* Return server_name if set */
        {
            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));
            EXPECT_SUCCESS(s2n_set_server_name(conn, test_server_name));

            const char* actual_server_name = NULL;
            EXPECT_NOT_NULL(actual_server_name = s2n_get_server_name(conn));
            EXPECT_STRING_EQUAL(actual_server_name, test_server_name);

            EXPECT_SUCCESS(s2n_connection_free(conn));
        }

        /* Return server_name if server_name extension parsed, but not yet processed */
        {
            struct s2n_connection *client_conn, *server_conn;
            EXPECT_NOT_NULL(client_conn = s2n_connection_new(S2N_CLIENT));
            EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));

            DEFER_CLEANUP(struct s2n_stuffer stuffer, s2n_stuffer_free);
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&stuffer, 0));
            EXPECT_SUCCESS(s2n_set_server_name(client_conn, test_server_name));
            EXPECT_SUCCESS(s2n_client_server_name_extension.send(client_conn, &stuffer));

            s2n_extension_type_id extension_id;
            EXPECT_SUCCESS(s2n_extension_supported_iana_value_to_id(TLS_EXTENSION_SERVER_NAME, &extension_id));
            server_conn->client_hello.extensions.parsed_extensions[extension_id].extension_type = TLS_EXTENSION_SERVER_NAME;
            server_conn->client_hello.extensions.parsed_extensions[extension_id].extension = stuffer.blob;

            const char* actual_server_name = NULL;
            EXPECT_NOT_NULL(actual_server_name = s2n_get_server_name(server_conn));
            EXPECT_STRING_EQUAL(actual_server_name, test_server_name);

            EXPECT_SUCCESS(s2n_connection_free(client_conn));
            EXPECT_SUCCESS(s2n_connection_free(server_conn));
        }

        /* Test retrieving server_name via ClientHello callback,
         * which is when we expect this API to be called. */
        {
            s2n_server_name_test_callback_flag = false;

            struct s2n_config *config;
            EXPECT_NOT_NULL(config = s2n_config_new());
            EXPECT_SUCCESS(s2n_config_set_client_hello_cb(config, s2n_server_name_test_callback, &test_server_name));

            struct s2n_connection *client_conn;
            EXPECT_NOT_NULL(client_conn = s2n_connection_new(S2N_CLIENT));
            EXPECT_SUCCESS(s2n_set_server_name(client_conn, test_server_name));

            struct s2n_connection *server_conn;
            EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));
            EXPECT_SUCCESS(s2n_connection_set_config(server_conn, config));

            EXPECT_SUCCESS(s2n_client_hello_send(client_conn));
            EXPECT_SUCCESS(s2n_stuffer_copy(&client_conn->handshake.io, &server_conn->handshake.io,
                    s2n_stuffer_data_available(&client_conn->handshake.io)));

            /* This function can succeed or fail -- it doesn't affect the test. */
            s2n_client_hello_recv(server_conn);

            /* Make sure the callback actually fired. If it did,
             * then the actual test ran and we have verified the server name. */
            EXPECT_TRUE(s2n_server_name_test_callback_flag);

            EXPECT_SUCCESS(s2n_connection_free(client_conn));
            EXPECT_SUCCESS(s2n_connection_free(server_conn));
            EXPECT_SUCCESS(s2n_config_free(config));
        }
    }

    /* s2n_connection_get_protocol_version */
    {
        struct s2n_connection *client_conn, *server_conn;
        EXPECT_NOT_NULL(client_conn = s2n_connection_new(S2N_CLIENT));
        EXPECT_SUCCESS(s2n_set_test_protocol_versions(client_conn));
        EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));
        EXPECT_SUCCESS(s2n_set_test_protocol_versions(server_conn));

        /* Handle null */
        EXPECT_EQUAL(s2n_connection_get_protocol_version(NULL), S2N_UNKNOWN_PROTOCOL_VERSION);

        /* Return actual if set */
        EXPECT_EQUAL(s2n_connection_get_protocol_version(client_conn), actual_version);
        EXPECT_EQUAL(s2n_connection_get_protocol_version(server_conn), actual_version);

        /* If actual version not set, result version for mode */
        client_conn->actual_protocol_version = S2N_UNKNOWN_PROTOCOL_VERSION;
        EXPECT_EQUAL(s2n_connection_get_protocol_version(client_conn), client_version);
        server_conn->actual_protocol_version = S2N_UNKNOWN_PROTOCOL_VERSION;
        EXPECT_EQUAL(s2n_connection_get_protocol_version(server_conn), server_version);

        EXPECT_SUCCESS(s2n_connection_free(client_conn));
        EXPECT_SUCCESS(s2n_connection_free(server_conn));
    }

    END_TEST();
}
