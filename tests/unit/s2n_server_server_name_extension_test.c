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
#include "tls/extensions/s2n_server_server_name.h"
#include "tls/s2n_connection.h"
#include "tls/s2n_handshake.h"

#define S2N_TEST_RESUMPTION_HANDSHAKE     (NEGOTIATED)
#define S2N_TEST_NOT_RESUMPTION_HANDSHAKE (NEGOTIATED | FULL_HANDSHAKE)

int main(int argc, char **argv)
{
    BEGIN_TEST();
    EXPECT_SUCCESS(s2n_disable_tls13_in_test());

    /* should_send */
    {
        struct s2n_connection *conn;
        EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));

        /* By default, do not send */
        EXPECT_FALSE(s2n_server_server_name_extension.should_send(conn));

        /* server_name not used and resumption handshake -> do not send */
        conn->server_name_used = false;
        conn->handshake.handshake_type = S2N_TEST_RESUMPTION_HANDSHAKE;
        EXPECT_FALSE(s2n_server_server_name_extension.should_send(conn));

        /* server_name used and resumption handshake -> do not send */
        conn->server_name_used = true;
        conn->handshake.handshake_type = S2N_TEST_RESUMPTION_HANDSHAKE;
        EXPECT_FALSE(s2n_server_server_name_extension.should_send(conn));

        /* server_name not used and not resumption handshake -> do not send */
        conn->server_name_used = false;
        conn->handshake.handshake_type = S2N_TEST_NOT_RESUMPTION_HANDSHAKE;
        EXPECT_FALSE(s2n_server_server_name_extension.should_send(conn));

        /* server_name used and not resumption handshake -> send */
        conn->server_name_used = true;
        conn->handshake.handshake_type = S2N_TEST_NOT_RESUMPTION_HANDSHAKE;
        EXPECT_TRUE(s2n_server_server_name_extension.should_send(conn));

        EXPECT_SUCCESS(s2n_connection_free(conn));
    };

    /* send */
    {
        /* Send writes nothing and always succeeds. */
        EXPECT_SUCCESS(s2n_server_server_name_extension.send(NULL, NULL));
    };

    /* recv */
    {
        struct s2n_connection *conn;
        EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));

        /* Recv reads nothing and always succeeds */
        EXPECT_FALSE(conn->server_name_used);
        EXPECT_SUCCESS(s2n_server_server_name_extension.recv(conn, NULL));
        EXPECT_TRUE(conn->server_name_used);

        EXPECT_SUCCESS(s2n_connection_free(conn));
    };

    END_TEST();
    return 0;
}
