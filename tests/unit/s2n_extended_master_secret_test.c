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
#include "utils/s2n_bitmap.h"

int main(int argc, char **argv)
{
    BEGIN_TEST();

    /* Test s2n_conn_set_handshake_type is processing EMS data correctly */
    {
        struct s2n_config *config;
        uint64_t current_time = 0;
        EXPECT_NOT_NULL(config = s2n_config_new());

        EXPECT_SUCCESS(s2n_config_set_session_tickets_onoff(config, 1));
        EXPECT_SUCCESS(config->wall_clock(config->sys_clock_ctx, &current_time));
        uint8_t ticket_key_name[16] = "2016.07.26.15\0";
        /**
         *= https://tools.ietf.org/rfc/rfc5869#appendix-A.1
         *# PRK  = 0x077709362c2e32df0ddc3f0dc47bba63
         *#        90b6c73bb50f9c3122ec844ad7c2b3e5 (32 octets)
         **/
        S2N_BLOB_FROM_HEX(ticket_key,
                "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5");
        EXPECT_SUCCESS(s2n_config_add_ticket_crypto_key(config, ticket_key_name, strlen((char *) ticket_key_name),
                ticket_key.data, ticket_key.size, current_time / ONE_SEC_IN_NANOS));

        /**
         *= https://tools.ietf.org/rfc/rfc7627#section-5.3
         *= type=test
         *# If the original session used the "extended_master_secret"
         *# extension but the new ClientHello does not contain it, the server
         *# MUST abort the abbreviated handshake.
         **/
        {
            struct s2n_connection *conn = s2n_connection_new(S2N_SERVER);
            EXPECT_NOT_NULL(conn);
            EXPECT_SUCCESS(s2n_connection_set_config(conn, config));
            conn->actual_protocol_version = S2N_TLS12;
            conn->secure->cipher_suite = &s2n_ecdhe_ecdsa_with_aes_128_gcm_sha256;
            /* Original connection negotiated an EMS */
            conn->ems_negotiated = true;

            struct s2n_stuffer ticket = { 0 };
            struct s2n_blob ticket_blob = { 0 };
            uint8_t ticket_data[S2N_TLS12_TICKET_SIZE_IN_BYTES] = { 0 };
            EXPECT_SUCCESS(s2n_blob_init(&ticket_blob, ticket_data, S2N_TLS12_TICKET_SIZE_IN_BYTES));
            EXPECT_SUCCESS(s2n_stuffer_init(&ticket, &ticket_blob));

            /* Encrypt the ticket with EMS data */
            EXPECT_SUCCESS(s2n_encrypt_session_ticket(conn, &ticket));

            EXPECT_SUCCESS(s2n_connection_wipe(conn));
            EXPECT_SUCCESS(s2n_connection_set_config(conn, config));
            conn->actual_protocol_version = S2N_TLS12;
            conn->secure->cipher_suite = &s2n_ecdhe_ecdsa_with_aes_128_gcm_sha256;
            conn->session_ticket_status = S2N_DECRYPT_TICKET;
            EXPECT_SUCCESS(s2n_stuffer_copy(&ticket, &conn->client_ticket_to_decrypt, S2N_TLS12_TICKET_SIZE_IN_BYTES));

            /* Resumed session did not receive the EMS extension */
            EXPECT_FAILURE_WITH_ERRNO(s2n_conn_set_handshake_type(conn), S2N_ERR_MISSING_EXTENSION);
            EXPECT_SUCCESS(s2n_connection_free(conn));
        };

        /**
         *= https://tools.ietf.org/rfc/rfc7627#section-5.3
         *= type=test
         *# If the original session did not use the "extended_master_secret"
         *# extension but the new ClientHello contains the extension, then the
         *# server MUST NOT perform the abbreviated handshake.  Instead, it
         *# SHOULD continue with a full handshake (as described in
         *# Section 5.2) to negotiate a new session.
         **/
        {
            struct s2n_connection *conn = s2n_connection_new(S2N_SERVER);
            EXPECT_NOT_NULL(conn);
            EXPECT_SUCCESS(s2n_connection_set_config(conn, config));
            conn->actual_protocol_version = S2N_TLS12;
            conn->secure->cipher_suite = &s2n_ecdhe_ecdsa_with_aes_128_gcm_sha256;
            /* Original connection did not negotiate an EMS */
            conn->ems_negotiated = false;

            struct s2n_stuffer ticket = { 0 };
            struct s2n_blob ticket_blob = { 0 };
            uint8_t ticket_data[S2N_TLS12_TICKET_SIZE_IN_BYTES] = { 0 };
            EXPECT_SUCCESS(s2n_blob_init(&ticket_blob, ticket_data, S2N_TLS12_TICKET_SIZE_IN_BYTES));
            EXPECT_SUCCESS(s2n_stuffer_init(&ticket, &ticket_blob));

            /* Encrypt the ticket without EMS data */
            EXPECT_SUCCESS(s2n_encrypt_session_ticket(conn, &ticket));

            EXPECT_SUCCESS(s2n_connection_wipe(conn));
            EXPECT_SUCCESS(s2n_connection_set_config(conn, config));
            conn->actual_protocol_version = S2N_TLS12;
            conn->secure->cipher_suite = &s2n_ecdhe_ecdsa_with_aes_128_gcm_sha256;
            conn->session_ticket_status = S2N_DECRYPT_TICKET;
            EXPECT_SUCCESS(s2n_stuffer_copy(&ticket, &conn->client_ticket_to_decrypt, S2N_TLS12_TICKET_SIZE_IN_BYTES));

            /* Resumed connection received the EMS extension */
            conn->ems_negotiated = true;

            EXPECT_SUCCESS(s2n_conn_set_handshake_type(conn));

            /* Fallback to full handshake */
            EXPECT_TRUE(s2n_handshake_type_check_flag(conn, FULL_HANDSHAKE));

            EXPECT_SUCCESS(s2n_connection_free(conn));
        };

        /* Session ticket is processed correctly if the previous session and current session both negotiated EMS */
        {
            struct s2n_connection *conn = s2n_connection_new(S2N_SERVER);
            EXPECT_NOT_NULL(conn);
            EXPECT_SUCCESS(s2n_connection_set_config(conn, config));
            conn->actual_protocol_version = S2N_TLS12;
            conn->secure->cipher_suite = &s2n_ecdhe_ecdsa_with_aes_128_gcm_sha256;
            /* Original connection negotiated an EMS */
            conn->ems_negotiated = true;

            struct s2n_stuffer ticket = { 0 };
            struct s2n_blob ticket_blob = { 0 };
            uint8_t ticket_data[S2N_TLS12_TICKET_SIZE_IN_BYTES] = { 0 };
            EXPECT_SUCCESS(s2n_blob_init(&ticket_blob, ticket_data, S2N_TLS12_TICKET_SIZE_IN_BYTES));
            EXPECT_SUCCESS(s2n_stuffer_init(&ticket, &ticket_blob));

            /* Encrypt the ticket with EMS data */
            EXPECT_SUCCESS(s2n_encrypt_session_ticket(conn, &ticket));

            EXPECT_SUCCESS(s2n_connection_wipe(conn));
            EXPECT_SUCCESS(s2n_connection_set_config(conn, config));
            conn->actual_protocol_version = S2N_TLS12;
            conn->secure->cipher_suite = &s2n_ecdhe_ecdsa_with_aes_128_gcm_sha256;
            conn->session_ticket_status = S2N_DECRYPT_TICKET;
            EXPECT_SUCCESS(s2n_stuffer_copy(&ticket, &conn->client_ticket_to_decrypt, S2N_TLS12_TICKET_SIZE_IN_BYTES));

            /* Resumed connection received the EMS extension */
            conn->ems_negotiated = true;
            s2n_extension_type_id ems_ext_id = 0;
            EXPECT_SUCCESS(s2n_extension_supported_iana_value_to_id(TLS_EXTENSION_EMS, &ems_ext_id));
            S2N_CBIT_SET(conn->extension_requests_received, ems_ext_id);

            EXPECT_SUCCESS(s2n_conn_set_handshake_type(conn));

            EXPECT_FALSE(s2n_handshake_type_check_flag(conn, FULL_HANDSHAKE));

            EXPECT_SUCCESS(s2n_connection_free(conn));
        };

        EXPECT_SUCCESS(s2n_config_free(config));
    };

    /* Connection where the client supports EMS but the server does not support EMS */
    {
        struct s2n_config *config = s2n_config_new();
        EXPECT_NOT_NULL(config);

        /* TLS1.2 cipher preferences */
        EXPECT_SUCCESS(s2n_config_set_cipher_preferences(config, "default"));
        EXPECT_SUCCESS(s2n_config_set_unsafe_for_testing(config));
        struct s2n_cert_chain_and_key *chain_and_key = NULL;
        EXPECT_SUCCESS(s2n_test_cert_chain_and_key_new(&chain_and_key,
                S2N_DEFAULT_TEST_CERT_CHAIN, S2N_DEFAULT_TEST_PRIVATE_KEY));
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(config, chain_and_key));

        struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT);
        EXPECT_NOT_NULL(client_conn);
        EXPECT_SUCCESS(s2n_connection_set_config(client_conn, config));

        struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER);
        EXPECT_NOT_NULL(server_conn);
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, config));

        /* Create nonblocking pipes */
        struct s2n_test_io_pair io_pair = { 0 };
        EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));
        EXPECT_SUCCESS(s2n_connections_set_io_pair(client_conn, server_conn, &io_pair));

        /* Negotiate until server has read the Client Hello message */
        s2n_blocked_status blocked = S2N_NOT_BLOCKED;
        EXPECT_OK(s2n_negotiate_until_message(client_conn, &blocked, SERVER_HELLO));
        EXPECT_OK(s2n_negotiate_until_message(server_conn, &blocked, SERVER_HELLO));

        /* s2n servers by default support EMS. We turn it off by manually setting ems_negotiated to false
         * and removing the EMS extension from our received extensions. */
        server_conn->ems_negotiated = false;
        s2n_extension_type_id ems_ext_id = 0;
        EXPECT_SUCCESS(s2n_extension_supported_iana_value_to_id(TLS_EXTENSION_EMS, &ems_ext_id));
        S2N_CBIT_CLR(server_conn->extension_requests_received, ems_ext_id);

        /* Connection is successful and EMS is not negotiated */
        EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));
        EXPECT_EQUAL(server_conn->actual_protocol_version, S2N_TLS12);
        EXPECT_EQUAL(client_conn->actual_protocol_version, S2N_TLS12);
        EXPECT_FALSE(server_conn->ems_negotiated);
        EXPECT_FALSE(client_conn->ems_negotiated);

        EXPECT_SUCCESS(s2n_connection_free(client_conn));
        EXPECT_SUCCESS(s2n_connection_free(server_conn));
        EXPECT_SUCCESS(s2n_io_pair_close(&io_pair));
        EXPECT_SUCCESS(s2n_cert_chain_and_key_free(chain_and_key));
        EXPECT_SUCCESS(s2n_config_free(config));
    };

    /* Connection where the server supports EMS but the client does not support EMS */
    {
        struct s2n_config *config = s2n_config_new();
        EXPECT_NOT_NULL(config);

        EXPECT_SUCCESS(s2n_config_set_cipher_preferences(config, "default"));
        EXPECT_SUCCESS(s2n_config_set_unsafe_for_testing(config));
        struct s2n_cert_chain_and_key *chain_and_key = NULL;
        EXPECT_SUCCESS(s2n_test_cert_chain_and_key_new(&chain_and_key,
                S2N_DEFAULT_TEST_CERT_CHAIN, S2N_DEFAULT_TEST_PRIVATE_KEY));
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(config, chain_and_key));

        struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT);
        EXPECT_NOT_NULL(client_conn);
        EXPECT_SUCCESS(s2n_connection_set_config(client_conn, config));

        struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER);
        EXPECT_NOT_NULL(server_conn);
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, config));

        /* Create nonblocking pipes */
        struct s2n_test_io_pair io_pair = { 0 };
        EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));
        EXPECT_SUCCESS(s2n_connections_set_io_pair(client_conn, server_conn, &io_pair));

        /* s2n clients support EMS by default. To manually prevent them from sending the EMS extension, add a 
         * resumption ticket to the connection, which indicates the previous session did not negotiate
         * EMS and therefore this session shouldn't either. The resumption ticket does not have to be valid
         * as this test is only interested in EMS. */
        client_conn->set_session = true;

        /* Connection is successful and EMS is not negotiated */
        EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));
        EXPECT_EQUAL(server_conn->actual_protocol_version, S2N_TLS12);
        EXPECT_EQUAL(client_conn->actual_protocol_version, S2N_TLS12);
        EXPECT_FALSE(server_conn->ems_negotiated);
        EXPECT_FALSE(client_conn->ems_negotiated);

        EXPECT_SUCCESS(s2n_connection_free(client_conn));
        EXPECT_SUCCESS(s2n_connection_free(server_conn));
        EXPECT_SUCCESS(s2n_cert_chain_and_key_free(chain_and_key));
        EXPECT_SUCCESS(s2n_io_pair_close(&io_pair));
        EXPECT_SUCCESS(s2n_config_free(config));
    };

    /* Connection where both client and server support EMS */
    {
        struct s2n_config *config = s2n_config_new();
        EXPECT_NOT_NULL(config);

        EXPECT_SUCCESS(s2n_config_set_cipher_preferences(config, "default"));
        EXPECT_SUCCESS(s2n_config_set_unsafe_for_testing(config));
        struct s2n_cert_chain_and_key *chain_and_key = NULL;
        EXPECT_SUCCESS(s2n_test_cert_chain_and_key_new(&chain_and_key,
                S2N_DEFAULT_TEST_CERT_CHAIN, S2N_DEFAULT_TEST_PRIVATE_KEY));
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(config, chain_and_key));

        struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT);
        EXPECT_NOT_NULL(client_conn);
        EXPECT_SUCCESS(s2n_connection_set_config(client_conn, config));

        struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER);
        EXPECT_NOT_NULL(server_conn);
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, config));

        /* Create nonblocking pipes */
        struct s2n_test_io_pair io_pair = { 0 };
        EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));
        EXPECT_SUCCESS(s2n_connections_set_io_pair(client_conn, server_conn, &io_pair));

        /* Connection is successful and EMS is negotiated */
        EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));
        EXPECT_EQUAL(server_conn->actual_protocol_version, S2N_TLS12);
        EXPECT_EQUAL(client_conn->actual_protocol_version, S2N_TLS12);
        EXPECT_TRUE(server_conn->ems_negotiated);
        EXPECT_TRUE(client_conn->ems_negotiated);

        EXPECT_SUCCESS(s2n_connection_free(client_conn));
        EXPECT_SUCCESS(s2n_connection_free(server_conn));
        EXPECT_SUCCESS(s2n_cert_chain_and_key_free(chain_and_key));
        EXPECT_SUCCESS(s2n_io_pair_close(&io_pair));
        EXPECT_SUCCESS(s2n_config_free(config));
    };

    END_TEST();
}
