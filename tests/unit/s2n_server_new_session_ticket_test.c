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

#include "tls/s2n_tls.h"
/* To test static functions */
#include "tls/s2n_server_new_session_ticket.c"

#define ONE_HOUR_IN_NANOS   3600000000000
#define TWO_HOURS_IN_NANOS  ONE_HOUR_IN_NANOS * 2
#define TICKET_AGE_ADD_MARKER sizeof(uint8_t)  + /* message id  */ \
                              SIZEOF_UINT24    + /* message len */ \
                              sizeof(uint32_t)   /* ticket lifetime */
#define RECORD_LEN_MARKER     sizeof(uint8_t) +  /* message type */ \
                              sizeof(uint16_t)   /* protocol version */

static int s2n_setup_test_keys(struct s2n_connection *conn, struct s2n_config *config)
{
    POSIX_ENSURE_REF(conn);
    POSIX_ENSURE_REF(config);

    /**
     *= https://tools.ietf.org/rfc/rfc5869#appendix-A.1
     *# PRK  = 0x077709362c2e32df0ddc3f0dc47bba63
     *#        90b6c73bb50f9c3122ec844ad7c2b3e5 (32 octets)
     **/
    S2N_BLOB_FROM_HEX(ticket_key,
    "077709362c2e32df0ddc3f0dc47bba63"
    "90b6c73bb50f9c3122ec844ad7c2b3e5");

    /**
     *= https://tools.ietf.org/rfc/rfc8448#section-3
     *# secret (32 octets):  18 df 06 84 3d 13 a0 8b f2 a4 49 84 4c 5f 8a
     *# 47 80 01 bc 4d 4c 62 79 84 d5 a4 1d a8 d0 40 29 19
     **/
    S2N_BLOB_FROM_HEX(test_master_secret,
    "18df06843d13a08bf2a449844c5f8a"
    "478001bc4d4c627984d5a41da8d0402919");

    /* Set up encryption key */
    uint64_t current_time;
    uint8_t ticket_key_name[16] = "2016.07.26.15\0";
    EXPECT_SUCCESS(s2n_config_set_session_tickets_onoff(config, 1));
    EXPECT_SUCCESS(config->wall_clock(config->sys_clock_ctx, &current_time));
    EXPECT_SUCCESS(s2n_config_add_ticket_crypto_key(config, ticket_key_name, strlen((char *)ticket_key_name),
                    ticket_key.data, ticket_key.size, current_time/ONE_SEC_IN_NANOS));

    EXPECT_SUCCESS(s2n_connection_set_config(conn, config));

    /* Set up master secret */
    struct s2n_blob secret = { 0 };
    struct s2n_stuffer secret_stuffer = { 0 };
    EXPECT_SUCCESS(s2n_blob_init(&secret, conn->secure.master_secret, S2N_TLS_SECRET_LEN));
    EXPECT_SUCCESS(s2n_stuffer_init(&secret_stuffer, &secret));
    EXPECT_SUCCESS(s2n_stuffer_write_bytes(&secret_stuffer, test_master_secret.data, test_master_secret.size));

    return S2N_SUCCESS;
}

int main(int argc, char **argv)
{
    BEGIN_TEST();

    /* s2n_tls13_server_nst_write */
    {
        /* Check session ticket message is correctly written. The contents of the 
         * message will be tested more thoroughly once the s2n_tls13_server_nst_recv 
         * function is written. */
        {
            struct s2n_config *config;
            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));
            EXPECT_NOT_NULL(config = s2n_config_new());
            EXPECT_SUCCESS(s2n_setup_test_keys(conn, config));

            conn->actual_protocol_version = S2N_TLS13;
            conn->secure.cipher_suite = &s2n_tls13_aes_256_gcm_sha384;
            uint16_t test_tickets_sent = 10;
            conn->tickets_sent = test_tickets_sent;

            /* Set up output stuffer */
            struct s2n_stuffer output = { 0 };
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&output, 0));
            
            EXPECT_SUCCESS(s2n_tls13_server_nst_write(conn, &output));

            uint8_t message_type = 0;
            EXPECT_SUCCESS(s2n_stuffer_read_uint8(&output, &message_type));
            EXPECT_EQUAL(TLS_SERVER_NEW_SESSION_TICKET, message_type);

            uint32_t message_size = 0;
            EXPECT_SUCCESS(s2n_stuffer_read_uint24(&output, &message_size));
            EXPECT_EQUAL(message_size, s2n_stuffer_data_available(&output));

            uint32_t ticket_lifetime = 0;
            EXPECT_SUCCESS(s2n_stuffer_read_uint32(&output, &ticket_lifetime));
            uint32_t key_lifetime_in_secs = S2N_TICKET_DECRYPT_KEY_LIFETIME_IN_NANOS / ONE_SEC_IN_NANOS;
            EXPECT_EQUAL(key_lifetime_in_secs, ticket_lifetime);

            /* Skipping random data */
            EXPECT_SUCCESS(s2n_stuffer_skip_read(&output, sizeof(uint32_t)));

            uint8_t ticket_nonce_len = 0;
            EXPECT_SUCCESS(s2n_stuffer_read_uint8(&output, &ticket_nonce_len));
            EXPECT_EQUAL(sizeof(uint16_t), ticket_nonce_len);

            uint8_t ticket_nonce[sizeof(uint16_t)] = { 0 };
            EXPECT_SUCCESS(s2n_stuffer_read_bytes(&output, ticket_nonce, ticket_nonce_len));

            uint8_t tickets_sent_array[sizeof(uint16_t)] = { 0 };
            struct s2n_blob blob = { 0 };
            EXPECT_SUCCESS(s2n_blob_init(&blob, tickets_sent_array, sizeof(uint16_t)));
            EXPECT_OK(s2n_generate_ticket_nonce(test_tickets_sent, &blob));
            EXPECT_BYTEARRAY_EQUAL(ticket_nonce, blob.data, ticket_nonce_len);

            uint8_t session_ticket_len = 0;
            EXPECT_SUCCESS(s2n_stuffer_read_uint8(&output, &session_ticket_len));
            uint8_t size_of_extensions_size = sizeof(uint16_t);
            EXPECT_EQUAL(session_ticket_len, (s2n_stuffer_data_available(&output) - size_of_extensions_size));

            /* Skipping encrypted ticket data */
            EXPECT_SUCCESS(s2n_stuffer_skip_read(&output, session_ticket_len));

            uint16_t extensions_len = 0;
            EXPECT_SUCCESS(s2n_stuffer_read_uint16(&output, &extensions_len));
            EXPECT_EQUAL(extensions_len, 0);

            EXPECT_TRUE(conn->tickets_sent == test_tickets_sent + 1);

            EXPECT_SUCCESS(s2n_connection_free(conn));
            EXPECT_SUCCESS(s2n_stuffer_free(&output));
            EXPECT_SUCCESS(s2n_config_free(config));
        }

        /* tickets_sent overflow */
        {
            struct s2n_config *config;
            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));
            EXPECT_NOT_NULL(config = s2n_config_new());
            EXPECT_SUCCESS(s2n_setup_test_keys(conn, config));

            conn->actual_protocol_version = S2N_TLS13;
            conn->secure.cipher_suite = &s2n_tls13_aes_256_gcm_sha384;
            conn->tickets_sent = UINT16_MAX;

            /* Set up output stuffer */
            struct s2n_stuffer output = { 0 };
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&output, 0));

            EXPECT_FAILURE_WITH_ERRNO(s2n_tls13_server_nst_write(conn, &output), S2N_ERR_INTEGER_OVERFLOW);

            EXPECT_SUCCESS(s2n_connection_free(conn));
            EXPECT_SUCCESS(s2n_stuffer_free(&output));
            EXPECT_SUCCESS(s2n_config_free(config));
        }

        /** ticket_age_add values do not repeat after sending multiple new session tickets
         *= https://tools.ietf.org/rfc/rfc8446#section-4.6.1
         *= type=test
         *#  The server MUST generate a fresh value
         *#  for each ticket it sends.
         **/
        {
            struct s2n_config *config;
            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));
            EXPECT_NOT_NULL(config = s2n_config_new());
            EXPECT_SUCCESS(s2n_setup_test_keys(conn, config));

            conn->actual_protocol_version = S2N_TLS13;
            conn->secure.cipher_suite = &s2n_tls13_aes_256_gcm_sha384;

            /* Set up output stuffer */
            struct s2n_stuffer output = { 0 };
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&output, 0));

            EXPECT_SUCCESS(s2n_tls13_server_nst_write(conn, &output));

            uint32_t original_ticket_age_add = 0;
            EXPECT_SUCCESS(s2n_stuffer_skip_read(&output, TICKET_AGE_ADD_MARKER));
            EXPECT_SUCCESS(s2n_stuffer_read_uint32(&output, &original_ticket_age_add));

            EXPECT_SUCCESS(s2n_stuffer_wipe(&output));
            EXPECT_SUCCESS(s2n_tls13_server_nst_write(conn, &output));

            uint32_t new_ticket_age_add = 0;
            EXPECT_SUCCESS(s2n_stuffer_skip_read(&output, TICKET_AGE_ADD_MARKER));
            EXPECT_SUCCESS(s2n_stuffer_read_uint32(&output, &new_ticket_age_add));

            EXPECT_NOT_EQUAL(original_ticket_age_add, new_ticket_age_add);

            EXPECT_SUCCESS(s2n_connection_free(conn));
            EXPECT_SUCCESS(s2n_stuffer_free(&output));
            EXPECT_SUCCESS(s2n_config_free(config));
        }
    }

    /* s2n_generate_ticket_lifetime */
    {
        uint32_t min_lifetime = 0;
        struct s2n_connection *conn;
        EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));

        /* Test: Decrypt key has shortest lifetime */
        conn->config->decrypt_key_lifetime_in_nanos = ONE_HOUR_IN_NANOS;
        conn->config->session_state_lifetime_in_nanos = TWO_HOURS_IN_NANOS;

        EXPECT_OK(s2n_generate_ticket_lifetime(conn, &min_lifetime));
        EXPECT_EQUAL(min_lifetime, conn->config->decrypt_key_lifetime_in_nanos / ONE_SEC_IN_NANOS);

        /* Test: Session state has shortest lifetime */
        conn->config->decrypt_key_lifetime_in_nanos = TWO_HOURS_IN_NANOS;
        conn->config->session_state_lifetime_in_nanos = ONE_HOUR_IN_NANOS;

        EXPECT_OK(s2n_generate_ticket_lifetime(conn, &min_lifetime));
        EXPECT_EQUAL(min_lifetime, conn->config->session_state_lifetime_in_nanos / ONE_SEC_IN_NANOS);        

        /** Test: Both session state and decrypt key have longer lifetimes than a week
         *= https://tools.ietf.org/rfc/rfc8446#section-4.6.1
         *= type=test
         *# Servers MUST NOT use any value greater than
         *# 604800 seconds (7 days).
         **/
        /* Note: We turn these integer literals into uint64_t values because otherwise
         * they will be interpreted as uint32_t values and an faulty integer overflow error
         * will be thrown. */
        uint64_t one_week_in_sec = ONE_WEEK_IN_SEC;
        uint64_t one_sec_in_nanos = ONE_SEC_IN_NANOS;
        uint64_t one_week_in_nanos = one_week_in_sec * one_sec_in_nanos;
        conn->config->decrypt_key_lifetime_in_nanos = one_week_in_nanos + 1;
        conn->config->session_state_lifetime_in_nanos = one_week_in_nanos + 1;

        EXPECT_OK(s2n_generate_ticket_lifetime(conn, &min_lifetime));
        EXPECT_EQUAL(min_lifetime, ONE_WEEK_IN_SEC);

        EXPECT_SUCCESS(s2n_connection_free(conn));
    }

    /* s2n_generate_ticket_nonce */
    {
        struct {
            uint16_t value;
            uint8_t expected_output[2];
        } test_cases[] = {
            { .value = 0, .expected_output = { 0 , 0 } },
            { .value = 1, .expected_output = { 0 , 1 } },
            { .value = 20, .expected_output = { 0 , 20 } },
            { .value = UINT8_MAX, .expected_output = { 0 , UINT8_MAX } },
            { .value = UINT8_MAX + 1, .expected_output = { 1 , 0 } },
            { .value = UINT16_MAX, .expected_output = { UINT8_MAX, UINT8_MAX } },
            { .value = UINT16_MAX - 1, .expected_output = { UINT8_MAX, UINT8_MAX - 1 } },
        };

        for (size_t i = 0; i < s2n_array_len(test_cases); i++) {
            uint8_t data[sizeof(uint16_t)] = { 0 };
            struct s2n_blob blob = { 0 };
            EXPECT_SUCCESS(s2n_blob_init(&blob, data, sizeof(data)));

            EXPECT_OK(s2n_generate_ticket_nonce(test_cases[i].value, &blob));

            EXPECT_EQUAL(test_cases[i].expected_output[0], data[0]);
            EXPECT_EQUAL(test_cases[i].expected_output[1], data[1]);
        }
    }

    /* s2n_generate_ticket_age_add */
    {
        struct {
            uint8_t value[4];
            uint32_t expected_output;
        } test_cases[] = {
            { .value = { 0, 0, 0, 0 }, .expected_output = 0 },
            { .value = { 0, 0, 0, 1 }, .expected_output = 1 },
            { .value = { 0, 0, 0, 20 }, .expected_output = 20 },
            { .value = { 0, 0, 1, 0 }, .expected_output = UINT8_MAX + 1 },
            { .value = { 0, 1, 0, 0 }, .expected_output = UINT16_MAX + 1 },
            { .value = { 0, 0, UINT8_MAX, UINT8_MAX }, .expected_output = UINT16_MAX },
            { .value = { UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX }, .expected_output = UINT32_MAX },
            { .value = { UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX - 1}, .expected_output = UINT32_MAX - 1 },
        };

        for (size_t i = 0; i < s2n_array_len(test_cases); i++) {
            uint32_t output = 0;
            struct s2n_blob blob = { 0 };
            EXPECT_SUCCESS(s2n_blob_init(&blob, test_cases[i].value, sizeof(test_cases[i].value)));
            EXPECT_OK(s2n_generate_ticket_age_add(&blob, &output));

            EXPECT_EQUAL(output, test_cases[i].expected_output);
        }
    }

    /* s2n_tls13_server_nst_send */
    {
        /* Mode is not server */
        {
            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));
            conn->actual_protocol_version = S2N_TLS13;
            conn->tickets_to_send = 1;

            /* Setup io */
            struct s2n_stuffer stuffer;
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&stuffer, 0));
            EXPECT_SUCCESS(s2n_connection_set_io_stuffers(&stuffer, &stuffer, conn));

            s2n_blocked_status blocked = 0;
            EXPECT_OK(s2n_tls13_server_nst_send(conn, &blocked));

            EXPECT_EQUAL(0, s2n_stuffer_data_available(&stuffer));

            EXPECT_SUCCESS(s2n_stuffer_free(&stuffer));
            EXPECT_SUCCESS(s2n_connection_free(conn));
        }

        /* Protocol is less than TLS13 */
        {
            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));
            conn->actual_protocol_version = S2N_TLS12;
            conn->tickets_to_send = 1;

            /* Setup io */
            struct s2n_stuffer stuffer;
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&stuffer, 0));
            EXPECT_SUCCESS(s2n_connection_set_io_stuffers(&stuffer, &stuffer, conn));

            s2n_blocked_status blocked = 0;
            EXPECT_OK(s2n_tls13_server_nst_send(conn, &blocked));

            EXPECT_EQUAL(0, s2n_stuffer_data_available(&stuffer));

            EXPECT_SUCCESS(s2n_stuffer_free(&stuffer));
            EXPECT_SUCCESS(s2n_connection_free(conn));
        }

        /* 0 tickets are requested */
        {
            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));
            conn->actual_protocol_version = S2N_TLS13;

            /* Setup io */
            struct s2n_stuffer stuffer;
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&stuffer, 0));
            EXPECT_SUCCESS(s2n_connection_set_io_stuffers(&stuffer, &stuffer, conn));

            s2n_blocked_status blocked = 0;
            EXPECT_OK(s2n_tls13_server_nst_send(conn, &blocked));

            EXPECT_EQUAL(0, s2n_stuffer_data_available(&stuffer));

            EXPECT_SUCCESS(s2n_stuffer_free(&stuffer));
            EXPECT_SUCCESS(s2n_connection_free(conn));
        }

        /* Sends one new session ticket */
        {
            struct s2n_config *config;
            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));
            EXPECT_NOT_NULL(config = s2n_config_new());
            EXPECT_SUCCESS(s2n_setup_test_keys(conn, config));

            conn->actual_protocol_version = S2N_TLS13;
            conn->secure.cipher_suite = &s2n_tls13_aes_128_gcm_sha256;
            conn->tickets_to_send = 1;

            /* Setup io */
            struct s2n_stuffer stuffer;
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&stuffer, 0));
            EXPECT_SUCCESS(s2n_connection_set_io_stuffers(&stuffer, &stuffer, conn));

            s2n_blocked_status blocked = 0;
            EXPECT_OK(s2n_tls13_server_nst_send(conn, &blocked));

            /* Check only one record was written */
            uint16_t record_len = 0;
            EXPECT_SUCCESS(s2n_stuffer_skip_read(&stuffer, RECORD_LEN_MARKER));
            EXPECT_SUCCESS(s2n_stuffer_read_uint16(&stuffer, &record_len));
            EXPECT_TRUE(record_len > 0);
            EXPECT_SUCCESS(s2n_stuffer_skip_read(&stuffer, record_len));
            EXPECT_TRUE(s2n_stuffer_data_available(&stuffer) == 0);

            EXPECT_SUCCESS(s2n_stuffer_free(&stuffer));
            EXPECT_SUCCESS(s2n_connection_free(conn));
            EXPECT_SUCCESS(s2n_config_free(config));
        }

        /* Sends multiple new session tickets */
        {
            struct s2n_config *config;
            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));
            EXPECT_NOT_NULL(config = s2n_config_new());
            EXPECT_SUCCESS(s2n_setup_test_keys(conn, config));

            conn->actual_protocol_version = S2N_TLS13;
            conn->secure.cipher_suite = &s2n_tls13_aes_128_gcm_sha256;
            uint16_t tickets_to_send = 5;
            conn->tickets_to_send = tickets_to_send;

            /* Setup io */
            struct s2n_stuffer stuffer;
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&stuffer, 0));
            EXPECT_SUCCESS(s2n_connection_set_io_stuffers(&stuffer, &stuffer, conn));

            s2n_blocked_status blocked = 0;
            EXPECT_OK(s2n_tls13_server_nst_send(conn, &blocked));

            /* Check five records were written */
            uint16_t record_len = 0;
            for (size_t i = 0; i < tickets_to_send; i++) {
                EXPECT_SUCCESS(s2n_stuffer_skip_read(&stuffer, RECORD_LEN_MARKER));
                EXPECT_SUCCESS(s2n_stuffer_read_uint16(&stuffer, &record_len));
                EXPECT_TRUE(record_len > 0);
                EXPECT_SUCCESS(s2n_stuffer_skip_read(&stuffer, record_len));
            }
            EXPECT_TRUE(s2n_stuffer_data_available(&stuffer) == 0);

            /* No more tickets to send */
            EXPECT_SUCCESS(s2n_stuffer_rewrite(&stuffer));
            EXPECT_OK(s2n_tls13_server_nst_send(conn, &blocked));
            EXPECT_EQUAL(0, s2n_stuffer_data_available(&stuffer));

            EXPECT_SUCCESS(s2n_stuffer_free(&stuffer));
            EXPECT_SUCCESS(s2n_connection_free(conn));
            EXPECT_SUCCESS(s2n_config_free(config));
        }
    }

    /* Functional test: s2n_negotiate sends new session tickets after the handshake is complete */
    {
        /* Setup connections */
        struct s2n_connection *client_conn, *server_conn;
        EXPECT_NOT_NULL(client_conn = s2n_connection_new(S2N_CLIENT));
        EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));

        /* Setup config */
        struct s2n_cert_chain_and_key *chain_and_key;
        EXPECT_SUCCESS(s2n_test_cert_chain_and_key_new(&chain_and_key,
                S2N_DEFAULT_ECDSA_TEST_CERT_CHAIN, S2N_DEFAULT_ECDSA_TEST_PRIVATE_KEY));
        struct s2n_config *config;
        EXPECT_NOT_NULL(config = s2n_config_new());
        EXPECT_SUCCESS(s2n_config_set_cipher_preferences(config, "default_tls13"));
        EXPECT_SUCCESS(s2n_config_set_unsafe_for_testing(config));
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(config, chain_and_key));
        EXPECT_SUCCESS(s2n_config_set_session_tickets_onoff(config, 1));
        EXPECT_SUCCESS(s2n_connection_set_config(client_conn, config));
        EXPECT_SUCCESS(s2n_setup_test_keys(server_conn, config));

        uint16_t tickets_to_send = 5;
        server_conn->tickets_to_send = tickets_to_send;

        struct s2n_stuffer client_to_server;
        struct s2n_stuffer server_to_client;

        EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&client_to_server, 0));
        EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&server_to_client, 0));

        EXPECT_SUCCESS(s2n_connection_set_io_stuffers(&server_to_client, &client_to_server, client_conn));
        EXPECT_SUCCESS(s2n_connection_set_io_stuffers(&client_to_server, &server_to_client, server_conn));

        /* Do handshake */
        EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));

        /* Check there are five records corresponding to five new session tickets
         * not read as part of the handshake */
        uint16_t record_len = 0;
        for (size_t i = 0; i < tickets_to_send; i++) {
            EXPECT_SUCCESS(s2n_stuffer_skip_read(&server_to_client, RECORD_LEN_MARKER));
            EXPECT_SUCCESS(s2n_stuffer_read_uint16(&server_to_client, &record_len));
            EXPECT_TRUE(record_len > 0);
            EXPECT_SUCCESS(s2n_stuffer_skip_read(&server_to_client, record_len));
        }
        EXPECT_TRUE(s2n_stuffer_data_available(&server_to_client) == 0);

        /* Call s2n_negotiate again to ensure no more tickets are sent */
        EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));
        EXPECT_EQUAL(0, s2n_stuffer_data_available(&server_to_client));

        EXPECT_SUCCESS(s2n_stuffer_free(&client_to_server));
        EXPECT_SUCCESS(s2n_stuffer_free(&server_to_client));
        EXPECT_SUCCESS(s2n_connection_free(server_conn));
        EXPECT_SUCCESS(s2n_connection_free(client_conn));
        EXPECT_SUCCESS(s2n_cert_chain_and_key_free(chain_and_key));
        EXPECT_SUCCESS(s2n_config_free(config));
    }
    END_TEST();
}
