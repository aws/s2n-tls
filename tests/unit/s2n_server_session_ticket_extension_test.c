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

#include <stdint.h>

#include "s2n_test.h"
#include "stuffer/s2n_stuffer.h"
#include "tls/extensions/s2n_server_session_ticket.h"
#include "tls/s2n_config.h"
#include "tls/s2n_connection.h"
#include "tls/s2n_tls.h"
#include "tls/s2n_tls13.h"
#include "utils/s2n_safety.h"

static int s2n_test_enable_extension(struct s2n_connection *conn)
{
    EXPECT_SUCCESS(s2n_config_set_session_tickets_onoff(conn->config, true));
    conn->session_ticket_status = S2N_NEW_TICKET;
    conn->actual_protocol_version = S2N_TLS12;
    return S2N_SUCCESS;
}

int main(int argc, char **argv)
{
    BEGIN_TEST();
    EXPECT_SUCCESS(s2n_disable_tls13_in_test());

    /* Test should_send */
    {
        struct s2n_config *config;
        EXPECT_NOT_NULL(config = s2n_config_new());

        struct s2n_connection *conn;
        EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));
        EXPECT_SUCCESS(s2n_connection_set_config(conn, config));

        /* By default, do not send */
        EXPECT_FALSE(s2n_server_session_ticket_extension.should_send(conn));

        /* If all prerequisites met, send */
        EXPECT_SUCCESS(s2n_test_enable_extension(conn));
        EXPECT_TRUE(s2n_server_session_ticket_extension.should_send(conn));

        /* If tickets not enabled, do not send */
        EXPECT_SUCCESS(s2n_test_enable_extension(conn));
        EXPECT_SUCCESS(s2n_config_set_session_tickets_onoff(config, false));
        EXPECT_FALSE(s2n_server_session_ticket_extension.should_send(conn));

        /* If ticket not new, do not send */
        EXPECT_SUCCESS(s2n_test_enable_extension(conn));
        conn->session_ticket_status = S2N_DECRYPT_TICKET;
        EXPECT_FALSE(s2n_server_session_ticket_extension.should_send(conn));

        /* If no ticket, do not send */
        EXPECT_SUCCESS(s2n_test_enable_extension(conn));
        conn->session_ticket_status = S2N_NO_TICKET;
        EXPECT_FALSE(s2n_server_session_ticket_extension.should_send(conn));

        /* If protocol version too high, do not send */
        EXPECT_SUCCESS(s2n_test_enable_extension(conn));
        conn->actual_protocol_version = S2N_TLS13;
        EXPECT_FALSE(s2n_server_session_ticket_extension.should_send(conn));

        EXPECT_SUCCESS(s2n_connection_free(conn));
        EXPECT_SUCCESS(s2n_config_free(config));
    };

    /* Test server_session_ticket send and recv */
    {
        struct s2n_connection *conn;
        EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));

        EXPECT_SUCCESS(s2n_server_session_ticket_extension.send(conn, NULL));

        EXPECT_EQUAL(conn->session_ticket_status, S2N_NO_TICKET);
        EXPECT_SUCCESS(s2n_server_session_ticket_extension.recv(conn, NULL));
        EXPECT_EQUAL(conn->session_ticket_status, S2N_NEW_TICKET);

        EXPECT_SUCCESS(s2n_connection_free(conn));
    };

    END_TEST();
    return 0;
}
