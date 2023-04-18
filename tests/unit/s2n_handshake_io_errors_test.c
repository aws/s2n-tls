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

#include "api/s2n.h"
#include "s2n_test.h"
#include "testlib/s2n_testlib.h"
#include "utils/s2n_result.h"

int main(int argc, char **argv)
{
    BEGIN_TEST();

    /* IO blocking on read does not close connection or invoke blinding */
    {
        struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER);
        EXPECT_NOT_NULL(server_conn);
        EXPECT_SUCCESS(s2n_connection_set_blinding(server_conn, S2N_SELF_SERVICE_BLINDING));
        EXPECT_SUCCESS(s2n_connection_set_cipher_preferences(server_conn, "default_tls13"));

        DEFER_CLEANUP(struct s2n_stuffer io_stuffer = { 0 }, s2n_stuffer_free);
        EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&io_stuffer, 0));
        EXPECT_SUCCESS(s2n_connection_set_io_stuffers(&io_stuffer, &io_stuffer, server_conn));

        /* Try to read the ClientHello, which hasn't been written yet */
        s2n_blocked_status blocked = S2N_NOT_BLOCKED;
        EXPECT_FAILURE_WITH_ERRNO(s2n_negotiate(server_conn, &blocked), S2N_ERR_IO_BLOCKED);

        /* Error did not close connection */
        EXPECT_TRUE(s2n_connection_check_io_status(server_conn, S2N_IO_FULL_DUPLEX));

        /* Error did not trigger blinding */
        EXPECT_EQUAL(s2n_connection_get_delay(server_conn), 0);

        EXPECT_SUCCESS(s2n_connection_free(server_conn));
    };

    /* Failure in read handler closes connection and invokes blinding */
    {
        s2n_blocked_status blocked = S2N_NOT_BLOCKED;

        struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT);
        EXPECT_NOT_NULL(client_conn);
        EXPECT_SUCCESS(s2n_connection_set_cipher_preferences(client_conn, "default_tls13"));

        struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER);
        EXPECT_NOT_NULL(server_conn);
        EXPECT_SUCCESS(s2n_connection_set_blinding(server_conn, S2N_SELF_SERVICE_BLINDING));
        EXPECT_SUCCESS(s2n_connection_set_cipher_preferences(server_conn, "default_tls13"));

        DEFER_CLEANUP(struct s2n_stuffer io_stuffer = { 0 }, s2n_stuffer_free);
        EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&io_stuffer, 0));
        EXPECT_SUCCESS(s2n_connection_set_io_stuffers(&io_stuffer, &io_stuffer, client_conn));
        EXPECT_SUCCESS(s2n_connection_set_io_stuffers(&io_stuffer, &io_stuffer, server_conn));

        /* Write the ClientHello */
        EXPECT_OK(s2n_negotiate_until_message(client_conn, &blocked, SERVER_HELLO));

        /* Overwrite everything except the headers */
        uint32_t content_size = s2n_stuffer_data_available(&io_stuffer)
                - S2N_TLS_RECORD_HEADER_LENGTH - TLS_HANDSHAKE_HEADER_LENGTH;
        EXPECT_SUCCESS(s2n_stuffer_wipe_n(&io_stuffer, content_size));
        EXPECT_SUCCESS(s2n_stuffer_skip_write(&io_stuffer, content_size));

        /* Read the ClientHello */
        EXPECT_ERROR_WITH_ERRNO(s2n_negotiate_until_message(server_conn, &blocked, SERVER_HELLO),
                S2N_ERR_BAD_MESSAGE);

        /* Error closes connection */
        EXPECT_TRUE(s2n_connection_check_io_status(server_conn, S2N_IO_CLOSED));

        /* Error triggers blinding */
        EXPECT_NOT_EQUAL(s2n_connection_get_delay(server_conn), 0);

        EXPECT_SUCCESS(s2n_connection_free(client_conn));
        EXPECT_SUCCESS(s2n_connection_free(server_conn));
    };

    /* Decrypt failure closes connection and invokes blinding */
    {
        s2n_blocked_status blocked = S2N_NOT_BLOCKED;

        struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT);
        EXPECT_NOT_NULL(client_conn);
        EXPECT_SUCCESS(s2n_connection_set_cipher_preferences(client_conn, "default_tls13"));

        struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER);
        EXPECT_NOT_NULL(server_conn);
        EXPECT_SUCCESS(s2n_connection_set_blinding(server_conn, S2N_SELF_SERVICE_BLINDING));
        EXPECT_SUCCESS(s2n_connection_set_cipher_preferences(server_conn, "default_tls13"));

        DEFER_CLEANUP(struct s2n_stuffer io_stuffer = { 0 }, s2n_stuffer_free);
        EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&io_stuffer, 0));
        EXPECT_SUCCESS(s2n_connection_set_io_stuffers(&io_stuffer, &io_stuffer, client_conn));
        EXPECT_SUCCESS(s2n_connection_set_io_stuffers(&io_stuffer, &io_stuffer, server_conn));

        /* Write the ClientHello */
        EXPECT_OK(s2n_negotiate_until_message(client_conn, &blocked, SERVER_HELLO));

        /* Set up encryption on the server */
        EXPECT_OK(s2n_connection_set_secrets(server_conn));

        /* Read the ClientHello */
        EXPECT_ERROR_WITH_ERRNO(s2n_negotiate_until_message(server_conn, &blocked, SERVER_HELLO),
                S2N_ERR_DECRYPT);

        /* Error closes connection */
        EXPECT_TRUE(s2n_connection_check_io_status(server_conn, S2N_IO_CLOSED));

        /* Error triggers blinding */
        EXPECT_NOT_EQUAL(s2n_connection_get_delay(server_conn), 0);

        EXPECT_SUCCESS(s2n_connection_free(client_conn));
        EXPECT_SUCCESS(s2n_connection_free(server_conn));
    };

    END_TEST();
}
