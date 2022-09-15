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

#include <stdint.h>

#include "tls/s2n_config.h"
#include "tls/s2n_connection.h"
#include "tls/s2n_tls.h"
#include "tls/s2n_tls13.h"
#include "tls/extensions/s2n_server_renegotiation_info.h"

#include "stuffer/s2n_stuffer.h"
#include "utils/s2n_safety.h"

int main(int argc, char **argv)
{
    BEGIN_TEST();
    EXPECT_SUCCESS(s2n_disable_tls13_in_test());

    /* Test should_send
     *
     *= https://tools.ietf.org/rfc/rfc5746#3.6
     *= type=test
     *# o  If the secure_renegotiation flag is set to TRUE, the server MUST
     *#    include an empty "renegotiation_info" extension in the ServerHello
     *#    message.
     */
    {
        struct s2n_connection *conn;
        EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));

        /* TLS1.2 and secure renegotiation not enabled -> DON'T send */
        conn->actual_protocol_version = S2N_TLS12;
        conn->secure_renegotiation = false;
        EXPECT_FALSE(s2n_server_renegotiation_info_extension.should_send(conn));

        /* TLS1.3 and secure renegotiation not enabled -> DON'T send */
        conn->actual_protocol_version = S2N_TLS13;
        conn->secure_renegotiation = false;
        EXPECT_FALSE(s2n_server_renegotiation_info_extension.should_send(conn));

        /* TLS1.3 and secure renegotiation enabled -> DON'T send */
        conn->actual_protocol_version = S2N_TLS13;
        conn->secure_renegotiation = true;
        EXPECT_FALSE(s2n_server_renegotiation_info_extension.should_send(conn));

        /* TLS1.2 and secure renegotiation enabled -> send */
        conn->actual_protocol_version = S2N_TLS12;
        conn->secure_renegotiation = true;
        EXPECT_TRUE(s2n_server_renegotiation_info_extension.should_send(conn));

        EXPECT_SUCCESS(s2n_connection_free(conn));
    }

    /* Test server_renegotiation_info send and recv */
    {
        struct s2n_connection *server_conn, *client_conn;
        EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));
        EXPECT_NOT_NULL(client_conn = s2n_connection_new(S2N_CLIENT));

        struct s2n_stuffer extension;
        EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&extension, 0));

        server_conn->actual_protocol_version = S2N_TLS12;
        server_conn->secure_renegotiation = 1;

        EXPECT_SUCCESS(s2n_server_renegotiation_info_extension.send(server_conn, &extension));
        EXPECT_NOT_EQUAL(s2n_stuffer_data_available(&extension), 0);

        EXPECT_SUCCESS(s2n_server_renegotiation_info_extension.recv(client_conn, &extension));
        EXPECT_EQUAL(client_conn->secure_renegotiation, 1);
        EXPECT_EQUAL(s2n_stuffer_data_available(&extension), 0);

        EXPECT_SUCCESS(s2n_stuffer_free(&extension));
        EXPECT_SUCCESS(s2n_connection_free(client_conn));
        EXPECT_SUCCESS(s2n_connection_free(server_conn));
    }

    /* Test server_renegotiation_info recv - extension too long */
    {
        struct s2n_connection *server_conn, *client_conn;
        EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));
        EXPECT_NOT_NULL(client_conn = s2n_connection_new(S2N_CLIENT));

        struct s2n_stuffer extension;
        EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&extension, 0));

        server_conn->actual_protocol_version = S2N_TLS12;
        server_conn->secure_renegotiation = 1;

        EXPECT_SUCCESS(s2n_server_renegotiation_info_extension.send(server_conn, &extension));
        EXPECT_SUCCESS(s2n_stuffer_write_uint8(&extension, 0));

        EXPECT_FAILURE_WITH_ERRNO(s2n_server_renegotiation_info_extension.recv(client_conn, &extension),
                S2N_ERR_NON_EMPTY_RENEGOTIATION_INFO);
        EXPECT_EQUAL(client_conn->secure_renegotiation, 0);

        EXPECT_SUCCESS(s2n_stuffer_free(&extension));
        EXPECT_SUCCESS(s2n_connection_free(client_conn));
        EXPECT_SUCCESS(s2n_connection_free(server_conn));
    }

    /* Test server_renegotiation_info recv - extension length wrong
     *
     *= https://tools.ietf.org/rfc/rfc5746#3.4
     *= type=test
     *# *  The client MUST then verify that the length of the
     *#    "renegotiated_connection" field is zero, and if it is not, MUST
     *#    abort the handshake (by sending a fatal handshake_failure alert).
     */
    {
        struct s2n_connection *client_conn;
        EXPECT_NOT_NULL(client_conn = s2n_connection_new(S2N_CLIENT));

        struct s2n_stuffer extension;
        EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&extension, 0));

        EXPECT_SUCCESS(s2n_stuffer_write_uint8(&extension, 5));

        EXPECT_FAILURE_WITH_ERRNO(s2n_server_renegotiation_info_extension.recv(client_conn, &extension),
                S2N_ERR_NON_EMPTY_RENEGOTIATION_INFO);
        EXPECT_EQUAL(client_conn->secure_renegotiation, 0);

        EXPECT_SUCCESS(s2n_stuffer_free(&extension));
        EXPECT_SUCCESS(s2n_connection_free(client_conn));
    }

    /* Functional Test
     *
     *= https://tools.ietf.org/rfc/rfc5746#3.4
     *= type=test
     *# o  When a ServerHello is received, the client MUST check if it
     *#    includes the "renegotiation_info" extension:
     */
    {
        DEFER_CLEANUP(struct s2n_cert_chain_and_key *chain_and_key = NULL, s2n_cert_chain_and_key_ptr_free);
        EXPECT_SUCCESS(s2n_test_cert_chain_and_key_new(&chain_and_key,
                S2N_DEFAULT_TEST_CERT_CHAIN, S2N_DEFAULT_TEST_PRIVATE_KEY));

        DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(), s2n_config_ptr_free);
        EXPECT_NOT_NULL(config);
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(config, chain_and_key));

        DEFER_CLEANUP(struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(client_conn);
        EXPECT_SUCCESS(s2n_connection_set_config(client_conn, config));

        DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(server_conn);
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, config));

        /* Send and receive the ClientHello */
        EXPECT_SUCCESS(s2n_client_hello_send(client_conn));
        EXPECT_SUCCESS(s2n_stuffer_copy(&client_conn->handshake.io, &server_conn->handshake.io,
                s2n_stuffer_data_available(&client_conn->handshake.io)));
        EXPECT_SUCCESS(s2n_client_hello_recv(server_conn));

        /* Test "renegotiation_info" extension NOT included */
        {
            EXPECT_FALSE(client_conn->secure_renegotiation);

            server_conn->secure_renegotiation = false;
            EXPECT_SUCCESS(s2n_server_hello_send(server_conn));
            EXPECT_SUCCESS(s2n_stuffer_copy(&server_conn->handshake.io, &client_conn->handshake.io,
                    s2n_stuffer_data_available(&server_conn->handshake.io)));
            EXPECT_SUCCESS(s2n_server_hello_recv(client_conn));

            EXPECT_FALSE(client_conn->secure_renegotiation);
        }

        /* Test "renegotiation_info" extension included */
        {
            EXPECT_FALSE(client_conn->secure_renegotiation);

            server_conn->secure_renegotiation = true;
            EXPECT_SUCCESS(s2n_server_hello_send(server_conn));
            EXPECT_SUCCESS(s2n_stuffer_copy(&server_conn->handshake.io, &client_conn->handshake.io,
                    s2n_stuffer_data_available(&server_conn->handshake.io)));
            EXPECT_SUCCESS(s2n_server_hello_recv(client_conn));

            EXPECT_TRUE(client_conn->secure_renegotiation);
        }
    }

    END_TEST();
    return 0;
}
