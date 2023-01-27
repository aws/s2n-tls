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
#include "tls/extensions/s2n_client_session_ticket.h"
#include "tls/s2n_resume.h"

/* Normally the session ticket is set by receiving a
 * new_session_ticket message. We'll just set it manually.
 */
static void s2n_set_test_ticket(struct s2n_connection *conn, const uint8_t *ticket_data, uint8_t ticket_data_len)
{
    EXPECT_SUCCESS(s2n_realloc(&conn->client_ticket, ticket_data_len));
    EXPECT_MEMCPY_SUCCESS(conn->client_ticket.data, ticket_data, ticket_data_len);
}

int main(int argc, char **argv)
{
    BEGIN_TEST();
    EXPECT_SUCCESS(s2n_disable_tls13_in_test());

    struct s2n_config *config;
    EXPECT_NOT_NULL(config = s2n_config_new());

    struct s2n_connection *client_conn;
    EXPECT_NOT_NULL(client_conn = s2n_connection_new(S2N_CLIENT));
    EXPECT_SUCCESS(s2n_connection_set_config(client_conn, config));

    /* should_send */
    {
        struct s2n_connection *conn;
        EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));
        EXPECT_SUCCESS(s2n_connection_set_config(conn, config));

        /* session ticket should NOT be sent if turned off */
        EXPECT_SUCCESS(s2n_config_set_session_tickets_onoff(config, false));
        EXPECT_FALSE(s2n_client_session_ticket_extension.should_send(conn));

        /* session ticket should be sent if turned on */
        EXPECT_SUCCESS(s2n_config_set_session_tickets_onoff(config, true));
        EXPECT_TRUE(s2n_client_session_ticket_extension.should_send(conn));

        /* session ticket should not be sent if TLS1.3 PSKs are being used */
        DEFER_CLEANUP(struct s2n_psk *test_psk = s2n_test_psk_new(conn), s2n_psk_free);
        EXPECT_SUCCESS(s2n_connection_append_psk(conn, test_psk));
        EXPECT_FALSE(s2n_client_session_ticket_extension.should_send(conn));

        EXPECT_SUCCESS(s2n_connection_free(conn));
    };

    EXPECT_SUCCESS(s2n_config_set_session_tickets_onoff(config, true));

    const uint8_t test_ticket[S2N_TLS12_TICKET_SIZE_IN_BYTES] = "TICKET";

    /* send */
    {
        struct s2n_stuffer stuffer = { 0 };
        EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&stuffer, 0));

        s2n_set_test_ticket(client_conn, test_ticket, s2n_array_len(test_ticket));

        EXPECT_SUCCESS(s2n_client_session_ticket_extension.send(client_conn, &stuffer));

        EXPECT_BYTEARRAY_EQUAL(stuffer.blob.data, test_ticket, s2n_array_len(test_ticket));

        EXPECT_SUCCESS(s2n_stuffer_free(&stuffer));
    };

    /* recv - decrypt ticket */
    {
        struct s2n_connection *server_conn;
        EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, config));

        struct s2n_stuffer stuffer = { 0 };
        EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&stuffer, 0));

        s2n_set_test_ticket(client_conn, test_ticket, S2N_TLS12_TICKET_SIZE_IN_BYTES);
        EXPECT_SUCCESS(s2n_client_session_ticket_extension.send(client_conn, &stuffer));

        EXPECT_EQUAL(server_conn->session_ticket_status, S2N_NO_TICKET);
        EXPECT_SUCCESS(s2n_client_session_ticket_extension.recv(server_conn, &stuffer));
        EXPECT_EQUAL(server_conn->session_ticket_status, S2N_DECRYPT_TICKET);
        EXPECT_BYTEARRAY_EQUAL(server_conn->client_ticket_to_decrypt.blob.data,
                test_ticket, s2n_array_len(test_ticket));

        EXPECT_SUCCESS(s2n_stuffer_free(&stuffer));
        EXPECT_SUCCESS(s2n_connection_free(server_conn));
    };

    /* recv - ignore extension if TLS1.3 */
    {
        struct s2n_connection *server_conn;
        EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, config));

        struct s2n_stuffer stuffer = { 0 };
        EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&stuffer, 0));

        s2n_set_test_ticket(client_conn, test_ticket, S2N_TLS12_TICKET_SIZE_IN_BYTES);
        EXPECT_SUCCESS(s2n_client_session_ticket_extension.send(client_conn, &stuffer));

        server_conn->actual_protocol_version = S2N_TLS13;
        EXPECT_SUCCESS(s2n_client_session_ticket_extension.recv(server_conn, &stuffer));
        EXPECT_EQUAL(server_conn->session_ticket_status, S2N_NO_TICKET);
        EXPECT_EQUAL(s2n_stuffer_data_available(&server_conn->client_ticket_to_decrypt), 0);

        server_conn->actual_protocol_version = S2N_TLS12;
        EXPECT_SUCCESS(s2n_client_session_ticket_extension.recv(server_conn, &stuffer));
        EXPECT_EQUAL(server_conn->session_ticket_status, S2N_DECRYPT_TICKET);

        EXPECT_SUCCESS(s2n_stuffer_free(&stuffer));
        EXPECT_SUCCESS(s2n_connection_free(server_conn));
    };

    /* recv - ignore extension if not correct size */
    {
        struct s2n_connection *server_conn;
        EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, config));

        struct s2n_stuffer stuffer = { 0 };
        EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&stuffer, 0));

        s2n_set_test_ticket(client_conn, test_ticket, S2N_TLS12_TICKET_SIZE_IN_BYTES - 1);
        EXPECT_SUCCESS(s2n_client_session_ticket_extension.send(client_conn, &stuffer));
        uint8_t extension_data = s2n_stuffer_data_available(&stuffer);

        EXPECT_SUCCESS(s2n_client_session_ticket_extension.recv(server_conn, &stuffer));
        EXPECT_EQUAL(server_conn->session_ticket_status, S2N_NO_TICKET);
        EXPECT_EQUAL(s2n_stuffer_data_available(&stuffer), extension_data);

        EXPECT_SUCCESS(s2n_stuffer_free(&stuffer));
        EXPECT_SUCCESS(s2n_connection_free(server_conn));
    };

    /* recv - ignore extension if tickets not allowed */
    {
        struct s2n_connection *server_conn;
        EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, config));

        struct s2n_stuffer stuffer = { 0 };
        EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&stuffer, 0));

        s2n_set_test_ticket(client_conn, test_ticket, S2N_TLS12_TICKET_SIZE_IN_BYTES);
        EXPECT_SUCCESS(s2n_client_session_ticket_extension.send(client_conn, &stuffer));
        uint8_t extension_data = s2n_stuffer_data_available(&stuffer);

        /* ignore if tickets not on */
        EXPECT_SUCCESS(s2n_config_set_session_tickets_onoff(config, false));
        EXPECT_SUCCESS(s2n_client_session_ticket_extension.recv(server_conn, &stuffer));
        EXPECT_EQUAL(server_conn->session_ticket_status, S2N_NO_TICKET);
        EXPECT_EQUAL(s2n_stuffer_data_available(&stuffer), extension_data);
        EXPECT_SUCCESS(s2n_config_set_session_tickets_onoff(config, true));

        /* ignore if client auth in use */
        EXPECT_SUCCESS(s2n_config_set_client_auth_type(config, S2N_CERT_AUTH_REQUIRED));
        EXPECT_SUCCESS(s2n_client_session_ticket_extension.recv(server_conn, &stuffer));
        EXPECT_EQUAL(server_conn->session_ticket_status, S2N_NO_TICKET);
        EXPECT_EQUAL(s2n_stuffer_data_available(&stuffer), extension_data);
        EXPECT_SUCCESS(s2n_config_set_client_auth_type(config, S2N_CERT_AUTH_NONE));

        /* When tickets on and client auth not in use, don't ignore */
        EXPECT_SUCCESS(s2n_client_session_ticket_extension.recv(server_conn, &stuffer));
        EXPECT_NOT_EQUAL(server_conn->session_ticket_status, S2N_NO_TICKET);

        EXPECT_SUCCESS(s2n_stuffer_free(&stuffer));
        EXPECT_SUCCESS(s2n_connection_free(server_conn));
    };

    EXPECT_SUCCESS(s2n_connection_free(client_conn));
    EXPECT_SUCCESS(s2n_config_free(config));

    END_TEST();
    return 0;
}
