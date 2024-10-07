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
#include "tls/extensions/s2n_server_alpn.h"
#include "tls/s2n_connection.h"

int main(int argc, char **argv)
{
    BEGIN_TEST();
    EXPECT_SUCCESS(s2n_disable_tls13_in_test());

    const char *test_protocol_name = "chosen_protocol";
    const uint8_t test_protocol_name_size = strlen(test_protocol_name);

    /* Test should_send */
    {
        struct s2n_connection *conn = NULL;
        EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));

        /* Should not send if protocol not set. Protocol not set by default. */
        EXPECT_FALSE(s2n_server_alpn_extension.should_send(conn));

        /* Should send if protocol set. */
        EXPECT_MEMCPY_SUCCESS(conn->application_protocol, test_protocol_name, test_protocol_name_size);
        EXPECT_TRUE(s2n_server_alpn_extension.should_send(conn));

        EXPECT_SUCCESS(s2n_connection_free(conn));
    };

    /* Test send */
    {
        struct s2n_connection *conn = NULL;
        EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));
        EXPECT_MEMCPY_SUCCESS(conn->application_protocol, test_protocol_name, test_protocol_name_size);

        struct s2n_stuffer stuffer = { 0 };
        EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&stuffer, 0));

        EXPECT_SUCCESS(s2n_server_alpn_extension.send(conn, &stuffer));

        /* Should have correct total size */
        uint16_t protocol_name_list_size = 0;
        EXPECT_SUCCESS(s2n_stuffer_read_uint16(&stuffer, &protocol_name_list_size));
        EXPECT_EQUAL(protocol_name_list_size, s2n_stuffer_data_available(&stuffer));

        /* Should have correct protocol name size */
        uint8_t protocol_name_size = 0;
        EXPECT_SUCCESS(s2n_stuffer_read_uint8(&stuffer, &protocol_name_size));
        EXPECT_EQUAL(protocol_name_size, s2n_stuffer_data_available(&stuffer));
        EXPECT_EQUAL(protocol_name_size, test_protocol_name_size);

        /* Should have correct protocol name */
        uint8_t *protocol_name = NULL;
        EXPECT_NOT_NULL(protocol_name = s2n_stuffer_raw_read(&stuffer, protocol_name_size));
        EXPECT_BYTEARRAY_EQUAL(protocol_name, test_protocol_name, test_protocol_name_size);

        EXPECT_SUCCESS(s2n_stuffer_free(&stuffer));
        EXPECT_SUCCESS(s2n_connection_free(conn));
    };

    /* Test recv */
    {
        struct s2n_connection *server_conn = NULL;
        EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));
        EXPECT_MEMCPY_SUCCESS(server_conn->application_protocol, test_protocol_name, test_protocol_name_size);

        /* Should accept extension written by send */
        {
            struct s2n_connection *client_conn = NULL;
            EXPECT_NOT_NULL(client_conn = s2n_connection_new(S2N_CLIENT));

            struct s2n_stuffer stuffer = { 0 };
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&stuffer, 0));

            EXPECT_SUCCESS(s2n_server_alpn_extension.send(server_conn, &stuffer));

            EXPECT_NULL(s2n_get_application_protocol(client_conn));
            EXPECT_SUCCESS(s2n_server_alpn_extension.recv(client_conn, &stuffer));
            EXPECT_NOT_NULL(s2n_get_application_protocol(client_conn));
            EXPECT_STRING_EQUAL(s2n_get_application_protocol(client_conn), test_protocol_name);

            EXPECT_EQUAL(s2n_stuffer_data_available(&stuffer), 0);

            EXPECT_SUCCESS(s2n_connection_free(client_conn));
            EXPECT_SUCCESS(s2n_stuffer_free(&stuffer));
        };

        /* Should ignore extension if protocol name list size incorrect */
        {
            struct s2n_connection *client_conn = NULL;
            EXPECT_NOT_NULL(client_conn = s2n_connection_new(S2N_CLIENT));

            struct s2n_stuffer stuffer = { 0 };
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&stuffer, 0));

            EXPECT_SUCCESS(s2n_server_alpn_extension.send(server_conn, &stuffer));
            EXPECT_SUCCESS(s2n_stuffer_wipe_n(&stuffer, 1));

            EXPECT_NULL(s2n_get_application_protocol(client_conn));
            EXPECT_SUCCESS(s2n_server_alpn_extension.recv(client_conn, &stuffer));
            EXPECT_NULL(s2n_get_application_protocol(client_conn));

            EXPECT_SUCCESS(s2n_connection_free(client_conn));
            EXPECT_SUCCESS(s2n_stuffer_free(&stuffer));
        };

        EXPECT_SUCCESS(s2n_connection_free(server_conn));
    };

    /* Send and receive maximum-sized alpn */
    {
        const uint8_t max_size = UINT8_MAX;

        DEFER_CLEANUP(struct s2n_connection *client = s2n_connection_new(S2N_CLIENT),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(client);
        EXPECT_NULL(s2n_get_application_protocol(client));

        DEFER_CLEANUP(struct s2n_connection *server = s2n_connection_new(S2N_SERVER),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(server);
        memset(server->application_protocol, 'a', sizeof(server->application_protocol) - 1);

        DEFER_CLEANUP(struct s2n_stuffer stuffer = { 0 }, s2n_stuffer_free);
        EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&stuffer, 0));
        EXPECT_SUCCESS(s2n_server_alpn_extension.send(server, &stuffer));
        EXPECT_SUCCESS(s2n_server_alpn_extension.recv(client, &stuffer));
        EXPECT_EQUAL(s2n_stuffer_data_available(&stuffer), 0);

        const char *client_alpn = s2n_get_application_protocol(client);
        EXPECT_NOT_NULL(client_alpn);
        EXPECT_EQUAL(strlen(client_alpn), max_size);
        EXPECT_STRING_EQUAL(client_alpn, server->application_protocol);
    };

    END_TEST();
    return 0;
}
