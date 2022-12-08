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
#include "tls/extensions/s2n_ems.h"
#include "tls/extensions/s2n_extension_list.h"
#include "tls/s2n_connection.h"

int main(int argc, char **argv)
{
    BEGIN_TEST();

    /* s2n_server_ems_should_send */
    {
        struct s2n_connection *conn = s2n_connection_new(S2N_SERVER);
        EXPECT_NOT_NULL(conn);

        /* Protocol version is too high */
        conn->actual_protocol_version = S2N_TLS13;
        EXPECT_FALSE(s2n_server_ems_extension.should_send(conn));

        /* Protocol version is less than TLS1.3 */
        conn->actual_protocol_version = S2N_TLS12;
        EXPECT_TRUE(s2n_server_ems_extension.should_send(conn));

        EXPECT_SUCCESS(s2n_connection_free(conn));
    };

    /* Test that the ems_negotiated flag is set when the EMS extension is received */
    {
        struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER);
        EXPECT_NOT_NULL(server_conn);

        struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT);
        EXPECT_NOT_NULL(client_conn);

        /* This extension is only relevant for TLS1.2 */
        server_conn->actual_protocol_version = S2N_TLS12;
        client_conn->actual_protocol_version = S2N_TLS12;

        DEFER_CLEANUP(struct s2n_stuffer stuffer, s2n_stuffer_free);
        EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&stuffer, 0));
        EXPECT_SUCCESS(s2n_extension_list_send(S2N_EXTENSION_LIST_CLIENT_HELLO, client_conn, &stuffer));
        EXPECT_FALSE(client_conn->ems_negotiated);

        EXPECT_SUCCESS(s2n_extension_list_recv(S2N_EXTENSION_LIST_CLIENT_HELLO, server_conn, &stuffer));
        EXPECT_TRUE(server_conn->ems_negotiated);

        EXPECT_SUCCESS(s2n_extension_list_send(S2N_EXTENSION_LIST_SERVER_HELLO_DEFAULT, server_conn, &stuffer));
        EXPECT_SUCCESS(s2n_extension_list_recv(S2N_EXTENSION_LIST_SERVER_HELLO_DEFAULT, client_conn, &stuffer));
        EXPECT_TRUE(client_conn->ems_negotiated);

        EXPECT_SUCCESS(s2n_connection_free(server_conn));
        EXPECT_SUCCESS(s2n_connection_free(client_conn));
    };

    /* s2n_server_ems_is_missing */
    {
        struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT);
        EXPECT_NOT_NULL(conn);

        /**
         *= https://tools.ietf.org/rfc/rfc7627#section-5.3
         *= type=test
         *#    If the original session used the extension but the new ServerHello
         *#    does not contain the extension, the client MUST abort the
         *#    handshake.
         **/
        conn->ems_negotiated = true;
        EXPECT_FAILURE_WITH_ERRNO(s2n_server_ems_extension.if_missing(conn), S2N_ERR_MISSING_EXTENSION);

        conn->ems_negotiated = false;
        EXPECT_SUCCESS(s2n_server_ems_extension.if_missing(conn));

        EXPECT_SUCCESS(s2n_connection_free(conn));
    };

    /* s2n_client_ems_should_send */
    {
        struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT);
        EXPECT_NOT_NULL(conn);

        /* In the default case we should always be sending this extension */
        EXPECT_TRUE(s2n_client_ems_extension.should_send(conn));

        conn->set_session = true;
        conn->ems_negotiated = true;
        /* If we have set a ticket on the connection we only send this extension
         * if the previous session negotiated EMS. */
        EXPECT_TRUE(s2n_client_ems_extension.should_send(conn));

        /* Don't send this extension if we have set a ticket on the connection
         * and the previous session did not negotiate EMS */
        conn->ems_negotiated = false;
        EXPECT_FALSE(s2n_client_ems_extension.should_send(conn));

        EXPECT_SUCCESS(s2n_connection_free(conn));
    };

    END_TEST();
}
