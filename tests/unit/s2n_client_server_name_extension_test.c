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
#include "tls/extensions/s2n_client_server_name.h"

int main(int argc, char **argv)
{
    BEGIN_TEST();
    EXPECT_SUCCESS(s2n_disable_tls13_in_test());

    const char *test_server_name = "github.com";

    /* should_send */
    {
        struct s2n_connection *conn;
        EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));

        /* server_name not set -> don't send */
        EXPECT_FALSE(s2n_client_server_name_extension.should_send(conn));

        /* server_name empty -> don't send */
        EXPECT_SUCCESS(s2n_set_server_name(conn, ""));
        EXPECT_FALSE(s2n_client_server_name_extension.should_send(conn));

        /* server_name set -> send */
        EXPECT_SUCCESS(s2n_set_server_name(conn, test_server_name));
        EXPECT_TRUE(s2n_client_server_name_extension.should_send(conn));

        EXPECT_SUCCESS(s2n_connection_free(conn));
    };

    /* send */
    {
        struct s2n_connection *conn;
        EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));
        EXPECT_SUCCESS(s2n_set_server_name(conn, test_server_name));

        struct s2n_stuffer stuffer = { 0 };
        EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&stuffer, 0));

        EXPECT_SUCCESS(s2n_client_server_name_extension.send(conn, &stuffer));

        uint16_t server_name_list_size;
        EXPECT_SUCCESS(s2n_stuffer_read_uint16(&stuffer, &server_name_list_size));
        EXPECT_EQUAL(server_name_list_size, s2n_stuffer_data_available(&stuffer));

        uint8_t name_type;
        EXPECT_SUCCESS(s2n_stuffer_read_uint8(&stuffer, &name_type));
        EXPECT_EQUAL(name_type, 0);

        uint16_t server_name_size;
        EXPECT_SUCCESS(s2n_stuffer_read_uint16(&stuffer, &server_name_size));
        EXPECT_EQUAL(server_name_size, s2n_stuffer_data_available(&stuffer));
        EXPECT_EQUAL(server_name_size, strlen(test_server_name));

        char *server_name_data;
        EXPECT_NOT_NULL(server_name_data = s2n_stuffer_raw_read(&stuffer, server_name_size));
        EXPECT_BYTEARRAY_EQUAL(server_name_data, test_server_name, strlen(test_server_name));

        EXPECT_EQUAL(s2n_stuffer_data_available(&stuffer), 0);

        EXPECT_SUCCESS(s2n_stuffer_free(&stuffer));
        EXPECT_SUCCESS(s2n_connection_free(conn));
    };

    /* recv - basic */
    {
        struct s2n_connection *client_conn;
        EXPECT_NOT_NULL(client_conn = s2n_connection_new(S2N_CLIENT));

        struct s2n_connection *server_conn;
        EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));

        struct s2n_stuffer stuffer = { 0 };
        EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&stuffer, 0));

        EXPECT_SUCCESS(s2n_set_server_name(client_conn, test_server_name));
        EXPECT_SUCCESS(s2n_client_server_name_extension.send(client_conn, &stuffer));

        EXPECT_STRING_EQUAL(server_conn->server_name, "");
        EXPECT_SUCCESS(s2n_client_server_name_extension.recv(server_conn, &stuffer));
        EXPECT_STRING_EQUAL(server_conn->server_name, test_server_name);

        EXPECT_EQUAL(s2n_stuffer_data_available(&stuffer), 0);

        EXPECT_SUCCESS(s2n_stuffer_free(&stuffer));
        EXPECT_SUCCESS(s2n_connection_free(client_conn));
        EXPECT_SUCCESS(s2n_connection_free(server_conn));
    };

    /* recv - server name already set */
    {
        struct s2n_connection *client_conn;
        EXPECT_NOT_NULL(client_conn = s2n_connection_new(S2N_CLIENT));

        struct s2n_connection *server_conn;
        EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_CLIENT));

        struct s2n_stuffer stuffer = { 0 };
        EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&stuffer, 0));

        EXPECT_SUCCESS(s2n_set_server_name(client_conn, "DIFFERENT SERVER NAME"));
        EXPECT_SUCCESS(s2n_client_server_name_extension.send(client_conn, &stuffer));

        EXPECT_SUCCESS(s2n_set_server_name(server_conn, test_server_name));
        EXPECT_SUCCESS(s2n_client_server_name_extension.recv(server_conn, &stuffer));
        EXPECT_STRING_EQUAL(server_conn->server_name, test_server_name);

        EXPECT_SUCCESS(s2n_stuffer_free(&stuffer));
        EXPECT_SUCCESS(s2n_connection_free(client_conn));
        EXPECT_SUCCESS(s2n_connection_free(server_conn));
    };

    /* recv - extra data ignored */
    {
        struct s2n_connection *client_conn;
        EXPECT_NOT_NULL(client_conn = s2n_connection_new(S2N_CLIENT));

        struct s2n_connection *server_conn;
        EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));

        struct s2n_stuffer stuffer = { 0 };
        EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&stuffer, 0));

        EXPECT_SUCCESS(s2n_set_server_name(client_conn, test_server_name));
        EXPECT_SUCCESS(s2n_client_server_name_extension.send(client_conn, &stuffer));
        EXPECT_SUCCESS(s2n_stuffer_write_uint8(&stuffer, 'a'));

        EXPECT_STRING_EQUAL(server_conn->server_name, "");
        EXPECT_SUCCESS(s2n_client_server_name_extension.recv(server_conn, &stuffer));
        EXPECT_STRING_EQUAL(server_conn->server_name, test_server_name);

        EXPECT_SUCCESS(s2n_stuffer_free(&stuffer));
        EXPECT_SUCCESS(s2n_connection_free(client_conn));
        EXPECT_SUCCESS(s2n_connection_free(server_conn));
    };

    /* recv - malformed */
    {
        struct s2n_connection *client_conn;
        EXPECT_NOT_NULL(client_conn = s2n_connection_new(S2N_CLIENT));

        struct s2n_connection *server_conn;
        EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));

        struct s2n_stuffer stuffer = { 0 };
        EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&stuffer, 0));

        EXPECT_SUCCESS(s2n_set_server_name(client_conn, test_server_name));
        EXPECT_SUCCESS(s2n_client_server_name_extension.send(client_conn, &stuffer));

        uint8_t extension_size = s2n_stuffer_data_available(&stuffer);
        uint8_t test_bytes = extension_size - strlen(test_server_name);

        /* Check that inverting any byte in the sizes / name type causes us to skip the extension */
        for (int i = 0; i < test_bytes; i++) {
            /* Mess something up! */
            stuffer.blob.data[i] = ~stuffer.blob.data[i];

            EXPECT_STRING_EQUAL(server_conn->server_name, "");
            EXPECT_SUCCESS(s2n_client_server_name_extension.recv(server_conn, &stuffer));
            EXPECT_STRING_EQUAL(server_conn->server_name, "");

            EXPECT_SUCCESS(s2n_stuffer_rewrite(&stuffer));
            EXPECT_SUCCESS(s2n_client_server_name_extension.send(client_conn, &stuffer));
        }

        /* Check that inverting a byte in the server name itself is fine-- there are
         * no real rules about the server name! */
        stuffer.blob.data[test_bytes] = ~stuffer.blob.data[test_bytes];

        EXPECT_STRING_EQUAL(server_conn->server_name, "");
        EXPECT_SUCCESS(s2n_client_server_name_extension.recv(server_conn, &stuffer));
        EXPECT_STRING_NOT_EQUAL(server_conn->server_name, "");

        EXPECT_SUCCESS(s2n_stuffer_free(&stuffer));
        EXPECT_SUCCESS(s2n_connection_free(client_conn));
        EXPECT_SUCCESS(s2n_connection_free(server_conn));
    };

    END_TEST();
    return 0;
}
