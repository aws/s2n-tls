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
#include "tls/s2n_connection.h"
#include "tls/s2n_post_handshake.h"
#include "tls/s2n_record.h"
#include "tls/s2n_tls13.h"
#include "tls/s2n_tls13_handshake.h"

#define MAX_TEST_SESSION_SIZE 300

uint8_t session_ticket_counter = 0;
static int s2n_test_session_ticket_cb(struct s2n_connection *conn, void *ctx, struct s2n_session_ticket *ticket)
{
    POSIX_ENSURE_REF(conn);
    POSIX_ENSURE_REF(ticket);

    size_t cb_session_data_len = 0;
    uint8_t cb_session_data[MAX_TEST_SESSION_SIZE] = { 0 };
    uint32_t cb_session_lifetime = 0;

    EXPECT_SUCCESS(s2n_session_ticket_get_data_len(ticket, &cb_session_data_len));
    EXPECT_TRUE(cb_session_data_len > 0);
    EXPECT_SUCCESS(s2n_session_ticket_get_data(ticket, cb_session_data_len, cb_session_data));
    EXPECT_NOT_NULL(cb_session_data);
    EXPECT_SUCCESS(s2n_session_ticket_get_lifetime(ticket, &cb_session_lifetime));
    EXPECT_TRUE(cb_session_lifetime > 0);

    session_ticket_counter++;

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
    uint8_t ticket_key_name[S2N_TICKET_KEY_NAME_LEN] = "2016.07.26.15\0";
    EXPECT_SUCCESS(config->wall_clock(config->sys_clock_ctx, &current_time));
    EXPECT_SUCCESS(s2n_config_add_ticket_crypto_key(config, ticket_key_name, strlen((char *) ticket_key_name),
            ticket_key.data, ticket_key.size, current_time / ONE_SEC_IN_NANOS));

    return S2N_SUCCESS;
}

int main(int argc, char **argv)
{
    BEGIN_TEST();

    if (!s2n_is_tls13_fully_supported()) {
        END_TEST();
    }

    /* s2n_send sends NewSessionTicket message and s2n_recv receives it */
    {
        struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER);
        struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT);
        EXPECT_NOT_NULL(server_conn);
        EXPECT_NOT_NULL(client_conn);

        struct s2n_config *server_config = s2n_config_new();
        EXPECT_NOT_NULL(server_config);

        struct s2n_config *client_config = s2n_config_new();
        EXPECT_NOT_NULL(client_config);

        struct s2n_cert_chain_and_key *chain_and_key;
        EXPECT_SUCCESS(s2n_test_cert_chain_and_key_new(&chain_and_key,
                S2N_DEFAULT_ECDSA_TEST_CERT_CHAIN, S2N_DEFAULT_ECDSA_TEST_PRIVATE_KEY));
        EXPECT_SUCCESS(s2n_config_set_session_tickets_onoff(server_config, 1));
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(server_config, chain_and_key));
        EXPECT_SUCCESS(s2n_setup_test_ticket_key(server_config));

        EXPECT_SUCCESS(s2n_config_set_session_tickets_onoff(client_config, 1));
        EXPECT_SUCCESS(s2n_config_set_session_ticket_cb(client_config, s2n_test_session_ticket_cb, NULL));
        EXPECT_SUCCESS(s2n_config_disable_x509_verification(client_config));

        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, server_config));
        EXPECT_SUCCESS(s2n_connection_set_config(client_conn, client_config));

        EXPECT_SUCCESS(s2n_connection_set_cipher_preferences(server_conn, "default_tls13"));
        EXPECT_SUCCESS(s2n_connection_set_cipher_preferences(client_conn, "default_tls13"));

        DEFER_CLEANUP(struct s2n_stuffer input, s2n_stuffer_free);
        DEFER_CLEANUP(struct s2n_stuffer output, s2n_stuffer_free);
        EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&input, 0));
        EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&output, 0));

        EXPECT_SUCCESS(s2n_connection_set_io_stuffers(&input, &output, server_conn));
        EXPECT_SUCCESS(s2n_connection_set_io_stuffers(&output, &input, client_conn));

        EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));

        /* Create conditions to send NewSessionTicket message */
        uint8_t tickets_to_send = 5;
        server_conn->tickets_to_send = tickets_to_send;

        /* Next message to send will trigger a NewSessionTicket message*/
        s2n_blocked_status blocked;
        uint8_t message[] = "sent message";
        EXPECT_SUCCESS(s2n_send(server_conn, message, sizeof(message), &blocked));

        /* Receive NewSessionTicket message */
        uint8_t data[sizeof(message)];
        EXPECT_SUCCESS(s2n_recv(client_conn, data, sizeof(data), &blocked));
        EXPECT_BYTEARRAY_EQUAL(data, message, sizeof(message));

        EXPECT_EQUAL(session_ticket_counter, tickets_to_send);

        EXPECT_SUCCESS(s2n_config_free(server_config));
        EXPECT_SUCCESS(s2n_config_free(client_config));
        EXPECT_SUCCESS(s2n_connection_free(server_conn));
        EXPECT_SUCCESS(s2n_connection_free(client_conn));
        EXPECT_SUCCESS(s2n_cert_chain_and_key_free(chain_and_key));
    };
    END_TEST();
}
