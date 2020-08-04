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

#include <s2n.h>

#include "tls/s2n_tls.h"
#include "tls/s2n_tls13.h"

#include "tls/extensions/s2n_cookie.h"

#include "utils/s2n_safety.h"

const uint8_t test_cookie_data[] =
    { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5 };
const uint8_t test_cookie_size = s2n_array_len(test_cookie_data);

int main(int argc, char *argv[])
{
    BEGIN_TEST();

    EXPECT_SUCCESS(s2n_enable_tls13());

    /* Test should_send */
    {
        struct s2n_connection *conn;
        EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));

        /* TLS1.2 and no cookie data: should not send */
        conn->actual_protocol_version = S2N_TLS12;
        EXPECT_SUCCESS(s2n_stuffer_wipe(&conn->cookie_stuffer));
        EXPECT_FALSE(s2n_server_cookie_extension.should_send(conn));

        /* TLS1.2 and cookie data: should not send */
        conn->actual_protocol_version = S2N_TLS12;
        EXPECT_SUCCESS(s2n_stuffer_write_uint8(&conn->cookie_stuffer, 0));
        EXPECT_FALSE(s2n_server_cookie_extension.should_send(conn));

        /* TLS1.3 and no cookie data: should not send */
        conn->actual_protocol_version = S2N_TLS13;
        EXPECT_SUCCESS(s2n_stuffer_wipe(&conn->cookie_stuffer));
        EXPECT_FALSE(s2n_server_cookie_extension.should_send(conn));

        /* TLS1.3 and cookie data: should send */
        conn->actual_protocol_version = S2N_TLS13;
        EXPECT_SUCCESS(s2n_stuffer_write_uint8(&conn->cookie_stuffer, 0));
        EXPECT_TRUE(s2n_server_cookie_extension.should_send(conn));

        EXPECT_SUCCESS(s2n_connection_free(conn));
    }

    /* Test send */
    {
        struct s2n_connection *conn;
        EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));

        struct s2n_stuffer stuffer;
        EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&stuffer, 0));

        EXPECT_SUCCESS(s2n_stuffer_write_bytes(&conn->cookie_stuffer, test_cookie_data, test_cookie_size));
        EXPECT_SUCCESS(s2n_server_cookie_extension.send(conn, &stuffer));

        uint16_t cookie_size;
        EXPECT_SUCCESS(s2n_stuffer_read_uint16(&stuffer, &cookie_size));
        EXPECT_EQUAL(cookie_size, s2n_stuffer_data_available(&stuffer));
        EXPECT_EQUAL(cookie_size, test_cookie_size);

        uint8_t *cookie_data;
        EXPECT_NOT_NULL(cookie_data = s2n_stuffer_raw_read(&stuffer, cookie_size));
        EXPECT_BYTEARRAY_EQUAL(cookie_data, test_cookie_data, test_cookie_size);

        EXPECT_EQUAL(s2n_stuffer_data_available(&stuffer), 0);

        /* Sending the extension should wipe the cookie stuffer */
        EXPECT_EQUAL(s2n_stuffer_data_available(&conn->cookie_stuffer), 0);

        EXPECT_SUCCESS(s2n_stuffer_free(&stuffer));
        EXPECT_SUCCESS(s2n_connection_free(conn));
    }

    /* Test recv */
    {
        struct s2n_connection *server_conn;
        EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));

        /* Should accept extension written by send */
        {
            EXPECT_SUCCESS(s2n_stuffer_write_bytes(&server_conn->cookie_stuffer,
                    test_cookie_data, test_cookie_size));

            struct s2n_connection *client_conn;
            EXPECT_NOT_NULL(client_conn = s2n_connection_new(S2N_SERVER));
            EXPECT_EQUAL(s2n_stuffer_data_available(&client_conn->cookie_stuffer), 0);

            struct s2n_stuffer stuffer;
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&stuffer, 0));

            EXPECT_SUCCESS(s2n_server_cookie_extension.send(server_conn, &stuffer));

            EXPECT_SUCCESS(s2n_server_cookie_extension.recv(client_conn, &stuffer));
            EXPECT_EQUAL(s2n_stuffer_data_available(&client_conn->cookie_stuffer), test_cookie_size);
            EXPECT_BYTEARRAY_EQUAL(client_conn->cookie_stuffer.blob.data,
                    test_cookie_data, test_cookie_size);
            EXPECT_EQUAL(s2n_stuffer_data_available(&stuffer), 0);

            EXPECT_SUCCESS(s2n_stuffer_free(&stuffer));
            EXPECT_SUCCESS(s2n_connection_free(client_conn));
        }

        /* Should do nothing if tls1.3 not enabled */
        {
            EXPECT_SUCCESS(s2n_stuffer_write_bytes(&server_conn->cookie_stuffer,
                    test_cookie_data, test_cookie_size));

            struct s2n_connection *client_conn;
            EXPECT_NOT_NULL(client_conn = s2n_connection_new(S2N_SERVER));
            EXPECT_EQUAL(s2n_stuffer_data_available(&client_conn->cookie_stuffer), 0);

            struct s2n_stuffer stuffer;
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&stuffer, 0));

            EXPECT_SUCCESS(s2n_server_cookie_extension.send(server_conn, &stuffer));

            EXPECT_SUCCESS(s2n_disable_tls13());
            EXPECT_SUCCESS(s2n_server_cookie_extension.recv(client_conn, &stuffer));
            EXPECT_EQUAL(s2n_stuffer_data_available(&client_conn->cookie_stuffer), 0);

            EXPECT_SUCCESS(s2n_enable_tls13());
            EXPECT_SUCCESS(s2n_stuffer_free(&stuffer));
            EXPECT_SUCCESS(s2n_connection_free(client_conn));
        }

        /* Should fail if cookie size wrong */
        {
            EXPECT_SUCCESS(s2n_stuffer_write_bytes(&server_conn->cookie_stuffer,
                    test_cookie_data, test_cookie_size));

            struct s2n_connection *client_conn;
            EXPECT_NOT_NULL(client_conn = s2n_connection_new(S2N_SERVER));
            EXPECT_EQUAL(s2n_stuffer_data_available(&client_conn->cookie_stuffer), 0);

            struct s2n_stuffer stuffer;
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&stuffer, 0));

            EXPECT_SUCCESS(s2n_server_cookie_extension.send(server_conn, &stuffer));
            EXPECT_SUCCESS(s2n_stuffer_wipe_n(&stuffer, 1));

            EXPECT_FAILURE(s2n_server_cookie_extension.recv(client_conn, &stuffer));
            EXPECT_EQUAL(s2n_stuffer_data_available(&client_conn->cookie_stuffer), 0);

            EXPECT_SUCCESS(s2n_stuffer_free(&stuffer));
            EXPECT_SUCCESS(s2n_connection_free(client_conn));
        }

        EXPECT_SUCCESS(s2n_connection_free(server_conn));
    }

    END_TEST();
    return 0;
}
