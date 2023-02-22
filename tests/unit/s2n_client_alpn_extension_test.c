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
#include "tls/extensions/s2n_client_alpn.h"

int main(int argc, char **argv)
{
    BEGIN_TEST();
    EXPECT_SUCCESS(s2n_disable_tls13_in_test());

    const char *protocols[] = { "protocol1", "protocol2", "protocol3" };
    const uint8_t protocols_count = s2n_array_len(protocols);

    /* Test should_send */
    {
        struct s2n_connection *conn;
        EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));

        EXPECT_SUCCESS(s2n_connection_set_protocol_preferences(conn, NULL, 0));
        EXPECT_FALSE(s2n_client_alpn_extension.should_send(conn));

        EXPECT_SUCCESS(s2n_connection_set_protocol_preferences(conn, protocols, protocols_count));
        EXPECT_TRUE(s2n_client_alpn_extension.should_send(conn));

        EXPECT_SUCCESS(s2n_connection_free(conn));
    };

    /* Test send */
    {
        struct s2n_connection *conn;
        EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));
        EXPECT_SUCCESS(s2n_connection_set_protocol_preferences(conn, protocols, protocols_count));

        struct s2n_stuffer stuffer = { 0 };
        EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&stuffer, 0));

        EXPECT_SUCCESS(s2n_client_alpn_extension.send(conn, &stuffer));

        /* Should have correct size */
        uint16_t actual_size;
        EXPECT_SUCCESS(s2n_stuffer_read_uint16(&stuffer, &actual_size));
        EXPECT_EQUAL(actual_size, s2n_stuffer_data_available(&stuffer));
        EXPECT_EQUAL(actual_size, conn->application_protocols_overridden.size);

        /* Should have correct data */
        uint8_t actual_data[256];
        EXPECT_SUCCESS(s2n_stuffer_read_bytes(&stuffer, actual_data, actual_size));
        EXPECT_BYTEARRAY_EQUAL(actual_data, conn->application_protocols_overridden.data, actual_size);

        EXPECT_SUCCESS(s2n_stuffer_free(&stuffer));
        EXPECT_SUCCESS(s2n_connection_free(conn));
    };

    /* Test receive can accept the output of send */
    {
        struct s2n_connection *conn;
        EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));
        EXPECT_SUCCESS(s2n_connection_set_protocol_preferences(conn, protocols, protocols_count));

        struct s2n_stuffer stuffer = { 0 };
        EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&stuffer, 0));

        EXPECT_SUCCESS(s2n_client_alpn_extension.send(conn, &stuffer));

        EXPECT_NULL(s2n_get_application_protocol(conn));
        EXPECT_SUCCESS(s2n_client_alpn_extension.recv(conn, &stuffer));
        EXPECT_NOT_NULL(s2n_get_application_protocol(conn));
        EXPECT_STRING_EQUAL(s2n_get_application_protocol(conn), protocols[0]);

        EXPECT_SUCCESS(s2n_connection_free(conn));
        EXPECT_SUCCESS(s2n_stuffer_free(&stuffer));
    };

    /* Test receive does nothing if no protocol preferences configured */
    {
        struct s2n_connection *conn;
        EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));

        struct s2n_stuffer stuffer = { 0 };
        EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&stuffer, 0));

        EXPECT_SUCCESS(s2n_client_alpn_extension.send(conn, &stuffer));

        EXPECT_NULL(s2n_get_application_protocol(conn));
        EXPECT_SUCCESS(s2n_client_alpn_extension.recv(conn, &stuffer));
        EXPECT_NULL(s2n_get_application_protocol(conn));

        EXPECT_SUCCESS(s2n_connection_free(conn));
        EXPECT_SUCCESS(s2n_stuffer_free(&stuffer));
    };

    /* Test receive does nothing if extension malformed */
    {
        struct s2n_connection *conn;
        EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));

        struct s2n_stuffer stuffer = { 0 };
        EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&stuffer, 0));

        EXPECT_SUCCESS(s2n_client_alpn_extension.send(conn, &stuffer));
        EXPECT_SUCCESS(s2n_stuffer_wipe_n(&stuffer, 1));

        EXPECT_NULL(s2n_get_application_protocol(conn));
        EXPECT_SUCCESS(s2n_client_alpn_extension.recv(conn, &stuffer));
        EXPECT_NULL(s2n_get_application_protocol(conn));

        EXPECT_SUCCESS(s2n_connection_free(conn));
        EXPECT_SUCCESS(s2n_stuffer_free(&stuffer));
    };

    END_TEST();
    return 0;
}
