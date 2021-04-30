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

#define ARE_FULL_HANDSHAKES(client, server) \
    (IS_FULL_HANDSHAKE(client) && IS_FULL_HANDSHAKE(server))

#define IS_HELLO_RETRY(client, server)                          \
    (((client->handshake.handshake_type) & HELLO_RETRY_REQUEST) \
     && ((server->handshake.handshake_type) & HELLO_RETRY_REQUEST))

static int s2n_test_session_ticket_cb(struct s2n_connection *conn, void *ctx, struct s2n_session_ticket *ticket)
{
    POSIX_ENSURE_REF(conn);
    POSIX_ENSURE_REF(ticket);

    size_t data_len = 0;
    EXPECT_SUCCESS(s2n_session_ticket_get_data_len(ticket, &data_len));

    struct s2n_stuffer *stuffer = (struct s2n_stuffer *) ctx;
    EXPECT_SUCCESS(s2n_stuffer_resize(stuffer, data_len));
    EXPECT_SUCCESS(s2n_session_ticket_get_data(ticket, data_len, stuffer->blob.data));
    EXPECT_SUCCESS(s2n_stuffer_skip_write(stuffer, data_len));

    return S2N_SUCCESS;
}

static int s2n_setup_test_ticket_key(struct s2n_config *config)
{
    POSIX_ENSURE_REF(config);

    /**
     *= https://tools.ietf.org/rfc/rfc5869#appendix-A.1
     *# PRK  = 0x077709362c2e32df0ddc3f0dc47bba63
     *#        90b6c73bb50f9c3122ec844ad7c2b3e5 (32 octets)
     **/
    S2N_BLOB_FROM_HEX(ticket_key,
    "077709362c2e32df0ddc3f0dc47bba63"
    "90b6c73bb50f9c3122ec844ad7c2b3e5");

    /* Set up encryption key */
    uint64_t current_time = 0;
    uint8_t ticket_key_name[16] = "2016.07.26.15\0";
    EXPECT_SUCCESS(s2n_config_set_session_tickets_onoff(config, 1));
    EXPECT_SUCCESS(config->wall_clock(config->sys_clock_ctx, &current_time));
    EXPECT_SUCCESS(s2n_config_add_ticket_crypto_key(config, ticket_key_name, strlen((char *)ticket_key_name),
                    ticket_key.data, ticket_key.size, current_time/ONE_SEC_IN_NANOS));

    return S2N_SUCCESS;
}

static S2N_RESULT s2n_test_recv_new_session_ticket(struct s2n_connection *conn)
{
    RESULT_ENSURE_REF(conn);

    s2n_blocked_status blocked = S2N_NOT_BLOCKED;
    uint8_t out = 0;
    EXPECT_FAILURE_WITH_ERRNO(s2n_recv(conn, &out, 1, &blocked), S2N_ERR_IO_BLOCKED);
    
    return S2N_RESULT_OK;
}

int main(int argc, char **argv)
{
    BEGIN_TEST();

    /* Setup server config */
    struct s2n_config *server_config = s2n_config_new();
    EXPECT_NOT_NULL(server_config);
    EXPECT_SUCCESS(s2n_config_set_cipher_preferences(server_config, "default_tls13"));
    EXPECT_SUCCESS(s2n_config_set_unsafe_for_testing(server_config));
    struct s2n_cert_chain_and_key *tls13_chain_and_key = NULL;
    EXPECT_SUCCESS(s2n_test_cert_chain_and_key_new(&tls13_chain_and_key, S2N_DEFAULT_ECDSA_TEST_CERT_CHAIN,
                                                   S2N_DEFAULT_ECDSA_TEST_PRIVATE_KEY));
    EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(server_config, tls13_chain_and_key));
    struct s2n_cert_chain_and_key *tls12_chain_and_key = NULL;
    EXPECT_SUCCESS(s2n_test_cert_chain_and_key_new(&tls12_chain_and_key, S2N_DEFAULT_TEST_CERT_CHAIN, 
                                                   S2N_DEFAULT_TEST_PRIVATE_KEY));
    EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(server_config, tls12_chain_and_key));
    EXPECT_SUCCESS(s2n_config_set_session_tickets_onoff(server_config, true));
    EXPECT_SUCCESS(s2n_setup_test_ticket_key(server_config));

    /* Setup TLS1.3 client config */
    struct s2n_config *tls13_client_config = s2n_config_new();
    EXPECT_NOT_NULL(tls13_client_config);
    EXPECT_SUCCESS(s2n_config_set_cipher_preferences(tls13_client_config, "default_tls13"));
    EXPECT_SUCCESS(s2n_config_set_unsafe_for_testing(tls13_client_config));
    EXPECT_SUCCESS(s2n_config_set_session_tickets_onoff(tls13_client_config, true));
    DEFER_CLEANUP(struct s2n_stuffer cb_session_data = { 0 }, s2n_stuffer_free);
    EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&cb_session_data, 0));
    EXPECT_SUCCESS(s2n_config_set_session_ticket_cb(tls13_client_config, s2n_test_session_ticket_cb, &cb_session_data));

    /* Setup TLS1.2 client config */
    struct s2n_config *tls12_client_config = s2n_config_new();
    EXPECT_NOT_NULL(tls12_client_config);
    EXPECT_SUCCESS(s2n_config_set_cipher_preferences(tls12_client_config, "20170210"));
    EXPECT_SUCCESS(s2n_config_set_unsafe_for_testing(tls12_client_config));
    EXPECT_SUCCESS(s2n_config_set_session_tickets_onoff(tls12_client_config, true));

    /* Test: Server and client resume a session multiple times */
    {
        struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT);
        struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER);
        EXPECT_NOT_NULL(client_conn);
        EXPECT_NOT_NULL(server_conn);

        EXPECT_SUCCESS(s2n_connection_set_config(client_conn, tls13_client_config));
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, server_config));

        /* Create nonblocking pipes */
        struct s2n_test_io_pair io_pair = { 0 };
        EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));
        EXPECT_SUCCESS(s2n_connections_set_io_pair(client_conn, server_conn, &io_pair));

        /* Negotiate initial handshake to get session ticket */
        EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));
        EXPECT_TRUE(ARE_FULL_HANDSHAKES(client_conn, server_conn));

        /* Receive and save the issued session ticket for the next connection */
        EXPECT_OK(s2n_test_recv_new_session_ticket(client_conn));

        for (size_t i = 0; i < 10; i++) {
            /* Prepare client and server for new connection */
            EXPECT_SUCCESS(s2n_connection_wipe(client_conn));
            EXPECT_SUCCESS(s2n_connection_wipe(server_conn));
            EXPECT_SUCCESS(s2n_connections_set_io_pair(client_conn, server_conn, &io_pair));

            /* Client sets up a resumption connection with the received session ticket data */
            size_t cb_session_data_len = s2n_stuffer_data_available(&cb_session_data);
            EXPECT_SUCCESS(s2n_connection_set_session(client_conn, cb_session_data.blob.data, cb_session_data_len));
            EXPECT_SUCCESS(s2n_stuffer_rewrite(&cb_session_data));

            /* Negotiate new connection */
            EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));
            EXPECT_FALSE(ARE_FULL_HANDSHAKES(client_conn, server_conn));

            /* Receive and save the issued session ticket for the next connection */
            EXPECT_OK(s2n_test_recv_new_session_ticket(client_conn));
        }

        EXPECT_SUCCESS(s2n_connection_free(server_conn));
        EXPECT_SUCCESS(s2n_connection_free(client_conn));
        EXPECT_SUCCESS(s2n_io_pair_close(&io_pair));
        EXPECT_SUCCESS(s2n_stuffer_rewrite(&cb_session_data));
    }

    /* Test: Server does not accept an expired ticket and instead does a full handshake */
    {
        struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT);
        struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER);
        EXPECT_NOT_NULL(client_conn);
        EXPECT_NOT_NULL(server_conn);

        EXPECT_SUCCESS(s2n_connection_set_config(client_conn, tls13_client_config));
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, server_config));

        /* Create nonblocking pipes */
        struct s2n_test_io_pair io_pair = { 0 };
        EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));
        EXPECT_SUCCESS(s2n_connections_set_io_pair(client_conn, server_conn, &io_pair));

        /* Negotiate initial handshake to get session ticket */
        EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));
        EXPECT_TRUE(ARE_FULL_HANDSHAKES(client_conn, server_conn));

        /* Receive and save the issued session ticket for the next connection */
        EXPECT_OK(s2n_test_recv_new_session_ticket(client_conn));

        /* Prepare client and server for new connection */
        EXPECT_SUCCESS(s2n_connection_wipe(client_conn));
        EXPECT_SUCCESS(s2n_connection_wipe(server_conn));
        EXPECT_SUCCESS(s2n_connections_set_io_pair(client_conn, server_conn, &io_pair));

        /* Client sets up a resumption connection with the received session ticket data */
        size_t cb_session_data_len = s2n_stuffer_data_available(&cb_session_data);
        EXPECT_SUCCESS(s2n_connection_set_session(client_conn, cb_session_data.blob.data, cb_session_data_len));
        EXPECT_SUCCESS(s2n_stuffer_rewrite(&cb_session_data));

        /* Setup conditions to make the server think the ticket has expired */
        EXPECT_SUCCESS(s2n_config_set_session_state_lifetime(server_config, 0));

        /* Negotiate new connection */
        EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));
        EXPECT_TRUE(ARE_FULL_HANDSHAKES(client_conn, server_conn));

        EXPECT_SUCCESS(s2n_connection_free(server_conn));
        EXPECT_SUCCESS(s2n_connection_free(client_conn));
        EXPECT_SUCCESS(s2n_io_pair_close(&io_pair));
        EXPECT_SUCCESS(s2n_stuffer_rewrite(&cb_session_data));
        EXPECT_SUCCESS(s2n_config_set_session_state_lifetime(server_config, S2N_STATE_LIFETIME_IN_NANOS));
    }

    /* Test: A TLS1.2 client with a valid TLS1.3 ticket falls back to a TLS1.2 connection */
    {
        struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT);
        struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER);
        EXPECT_NOT_NULL(client_conn);
        EXPECT_NOT_NULL(server_conn);

        EXPECT_SUCCESS(s2n_connection_set_config(client_conn, tls13_client_config));
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, server_config));

        /* Create nonblocking pipes */
        struct s2n_test_io_pair io_pair = { 0 };
        EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));
        EXPECT_SUCCESS(s2n_connections_set_io_pair(client_conn, server_conn, &io_pair));

        /* Negotiate initial handshake to produce TLS1.3 session ticket */
        EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));
        EXPECT_TRUE(ARE_FULL_HANDSHAKES(client_conn, server_conn));

        /* Receive and save the issued session ticket for the next connection */
        EXPECT_OK(s2n_test_recv_new_session_ticket(client_conn));

        /* Prepare client and server for a second connection */
        EXPECT_SUCCESS(s2n_connection_wipe(client_conn));
        EXPECT_SUCCESS(s2n_connection_wipe(server_conn));
        EXPECT_SUCCESS(s2n_connections_set_io_pair(client_conn, server_conn, &io_pair));

        /* Client sets up a resumption connection with the received session ticket data */
        size_t cb_session_data_len = s2n_stuffer_data_available(&cb_session_data);
        EXPECT_SUCCESS(s2n_connection_set_session(client_conn, cb_session_data.blob.data, cb_session_data_len));
        EXPECT_SUCCESS(s2n_stuffer_rewrite(&cb_session_data));

        /* Set client config to TLS1.2 cipher preferences */
        EXPECT_SUCCESS(s2n_connection_set_config(client_conn, tls12_client_config));

        /* Negotiate second connection */
        EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));

        /* Falls back to TLS1.2 handshake */
        EXPECT_TRUE(ARE_FULL_HANDSHAKES(client_conn, server_conn));
        EXPECT_EQUAL(client_conn->actual_protocol_version, S2N_TLS12);
        EXPECT_EQUAL(server_conn->actual_protocol_version, S2N_TLS12);

        EXPECT_SUCCESS(s2n_connection_free(server_conn));
        EXPECT_SUCCESS(s2n_connection_free(client_conn));
        EXPECT_SUCCESS(s2n_io_pair_close(&io_pair));
    }

    /* Test: A client with a valid TLS1.2 session ticket and TLS1.3 cipher preferences
     * will fail connecting to a TLS1.3 server. This is because the server
     * interprets the client as a TLS1.2 client and sends the client a TLS1.2 Server Hello.
     * The client receives this TLS1.2 Server Hello and errors, because the client 
     * views the TLS1.2 Server Hello as a downgrade attack, given that the client advertised
     * its TLS1.3 ability in the Client Hello.
     */
    {
        struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT);
        struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER);
        EXPECT_NOT_NULL(client_conn);
        EXPECT_NOT_NULL(server_conn);

        EXPECT_SUCCESS(s2n_connection_set_config(client_conn, tls12_client_config));
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, server_config));

        /* Create nonblocking pipes */
        struct s2n_test_io_pair io_pair = { 0 };
        EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));
        EXPECT_SUCCESS(s2n_connections_set_io_pair(client_conn, server_conn, &io_pair));

        /* Negotiate initial handshake to produce TLS1.2 session ticket */
        EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));
        EXPECT_TRUE(ARE_FULL_HANDSHAKES(client_conn, server_conn));
        EXPECT_TRUE(IS_ISSUING_NEW_SESSION_TICKET(server_conn));

        /* Store the TLS1.2 session ticket */
        size_t tls12_session_ticket_len = s2n_connection_get_session_length(client_conn);
        uint8_t tls12_session_ticket[S2N_TLS12_SESSION_SIZE] = { 0 };
        EXPECT_SUCCESS(s2n_connection_get_session(client_conn, tls12_session_ticket, tls12_session_ticket_len));

        /* Prepare client and server for a second connection */
        EXPECT_SUCCESS(s2n_connection_wipe(client_conn));
        EXPECT_SUCCESS(s2n_connection_wipe(server_conn));
        EXPECT_SUCCESS(s2n_connections_set_io_pair(client_conn, server_conn, &io_pair));
        EXPECT_SUCCESS(s2n_connection_set_blinding(client_conn, S2N_SELF_SERVICE_BLINDING));

        /* Client sets up a resumption connection with the received TLS1.2 session ticket data */
        EXPECT_SUCCESS(s2n_connection_set_session(client_conn, tls12_session_ticket, tls12_session_ticket_len));

        /* Set client config to TLS1.3 cipher preferences */
        EXPECT_SUCCESS(s2n_connection_set_config(client_conn, tls13_client_config));

        /* Negotiate second connection */
        EXPECT_FAILURE_WITH_ERRNO(s2n_negotiate_test_server_and_client(server_conn, client_conn), S2N_ERR_PROTOCOL_DOWNGRADE_DETECTED);

        EXPECT_SUCCESS(s2n_connection_free(server_conn));
        EXPECT_SUCCESS(s2n_connection_free(client_conn));
        EXPECT_SUCCESS(s2n_io_pair_close(&io_pair));
    }

    /* HRR when issuing a session resumption ticket and when resuming a session */
    {
        struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT);
        struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER);
        EXPECT_NOT_NULL(client_conn);
        EXPECT_NOT_NULL(server_conn);

        EXPECT_SUCCESS(s2n_connection_set_config(client_conn, tls13_client_config));
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, server_config));

        /* Create nonblocking pipes */
        struct s2n_test_io_pair io_pair = { 0 };
        EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));
        EXPECT_SUCCESS(s2n_connections_set_io_pair(client_conn, server_conn, &io_pair));

        EXPECT_SUCCESS(s2n_connection_set_keyshare_by_name_for_testing(client_conn, "none"));

        /* Negotiate handshake */
        EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));

        /* Validate handshake type */
        EXPECT_TRUE(ARE_FULL_HANDSHAKES(client_conn, server_conn));
        EXPECT_TRUE(IS_HELLO_RETRY(client_conn, server_conn));

        /* Receive and save the issued session ticket for the next connection */
        EXPECT_OK(s2n_test_recv_new_session_ticket(client_conn));

        /* Prepare client and server for new connection */
        EXPECT_SUCCESS(s2n_connection_wipe(client_conn));
        EXPECT_SUCCESS(s2n_connection_wipe(server_conn));
        EXPECT_SUCCESS(s2n_connections_set_io_pair(client_conn, server_conn, &io_pair));

        EXPECT_SUCCESS(s2n_connection_set_keyshare_by_name_for_testing(client_conn, "none"));

        /* Client sets up a resumption connection with the received session ticket data */
        size_t cb_session_data_len = s2n_stuffer_data_available(&cb_session_data);
        EXPECT_SUCCESS(s2n_connection_set_session(client_conn, cb_session_data.blob.data, cb_session_data_len));
        EXPECT_SUCCESS(s2n_stuffer_rewrite(&cb_session_data));

        /* Negotiate new connection */
        EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));
        EXPECT_FALSE(ARE_FULL_HANDSHAKES(client_conn, server_conn));
        EXPECT_TRUE(IS_HELLO_RETRY(client_conn, server_conn));

        EXPECT_SUCCESS(s2n_connection_free(server_conn));
        EXPECT_SUCCESS(s2n_connection_free(client_conn));
        EXPECT_SUCCESS(s2n_io_pair_close(&io_pair));
    }

    /* Clean-up */
    EXPECT_SUCCESS(s2n_config_free(server_config));
    EXPECT_SUCCESS(s2n_config_free(tls13_client_config));
    EXPECT_SUCCESS(s2n_config_free(tls12_client_config));
    EXPECT_SUCCESS(s2n_cert_chain_and_key_free(tls13_chain_and_key));
    EXPECT_SUCCESS(s2n_cert_chain_and_key_free(tls12_chain_and_key));

    END_TEST();
}
