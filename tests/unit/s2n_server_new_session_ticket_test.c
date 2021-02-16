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

#include "tls/s2n_tls.h"
/* To test static functions */
#include "tls/s2n_server_new_session_ticket.c"

#define ONE_HOUR_IN_NANOS   3600000000000
#define TWO_HOURS_IN_NANOS  ONE_HOUR_IN_NANOS * 2

int main(int argc, char **argv)
{
    BEGIN_TEST();
    
    /* s2n_tls13_server_nst_send */
    {
        /* Session ticket keys. Taken from test vectors in https://tools.ietf.org/html/rfc5869 */
            uint8_t ticket_key_name[16] = "2016.07.26.15\0";
            S2N_BLOB_FROM_HEX(ticket_key, 
            "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5");

            S2N_BLOB_FROM_HEX(test_master_secret,
            "ee85dd54781bd4d8a100589a9fe6ac9a3797b811e977f549cd"
            "531be2441d7c63e2b9729d145c11d84af35957727565a4");

        /* Check session ticket message is correctly written. The contents of the 
         * message will be tested more thoroughly once the s2n_tls13_server_nst_recv 
         * function is written. */
        {
            struct s2n_config *config;
            uint64_t current_time;
            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));
            EXPECT_NOT_NULL(config = s2n_config_new());
            conn->actual_protocol_version = S2N_TLS13;
            conn->secure.cipher_suite = &s2n_tls13_aes_256_gcm_sha384;
            uint16_t test_tickets_sent = 10;
            conn->tickets_sent = test_tickets_sent;

            /* Set up encryption key */
            EXPECT_SUCCESS(s2n_config_set_session_tickets_onoff(config, 1));
            EXPECT_SUCCESS(config->wall_clock(config->sys_clock_ctx, &current_time));
            EXPECT_SUCCESS(s2n_config_add_ticket_crypto_key(config, ticket_key_name, strlen((char *)ticket_key_name),
                         ticket_key.data, sizeof(ticket_key), current_time/ONE_SEC_IN_NANOS));
            
            EXPECT_SUCCESS(s2n_connection_set_config(conn, config));

            /* Set up master resumption secret */
            struct s2n_blob secret = { 0 };
            struct s2n_stuffer secret_stuffer = { 0 };
            EXPECT_SUCCESS(s2n_blob_init(&secret, conn->secure.master_secret, S2N_TLS_SECRET_LEN));
            EXPECT_SUCCESS(s2n_stuffer_init(&secret_stuffer, &secret));
            EXPECT_SUCCESS(s2n_stuffer_write_bytes(&secret_stuffer, test_master_secret.data, S2N_TLS_SECRET_LEN));
            
            EXPECT_SUCCESS(s2n_tls13_server_nst_send(conn));

            uint8_t message_type = 0;
            EXPECT_SUCCESS(s2n_stuffer_read_uint8(&conn->handshake.io, &message_type));
            EXPECT_EQUAL(TLS_SERVER_NEW_SESSION_TICKET, message_type);

            uint32_t message_size = 0;
            EXPECT_SUCCESS(s2n_stuffer_read_uint24(&conn->handshake.io, &message_size));
            EXPECT_EQUAL(message_size, s2n_stuffer_data_available(&conn->handshake.io));

            uint32_t ticket_lifetime = 0;
            EXPECT_SUCCESS(s2n_stuffer_read_uint32(&conn->handshake.io, &ticket_lifetime));
            uint32_t key_lifetime_in_secs = S2N_TICKET_DECRYPT_KEY_LIFETIME_IN_NANOS / ONE_SEC_IN_NANOS;
            EXPECT_EQUAL(key_lifetime_in_secs, ticket_lifetime);

            /* Skipping random data */
            EXPECT_SUCCESS(s2n_stuffer_skip_read(&conn->handshake.io, sizeof(uint32_t)));

            uint8_t ticket_nonce_len = 0;
            EXPECT_SUCCESS(s2n_stuffer_read_uint8(&conn->handshake.io, &ticket_nonce_len));
            EXPECT_EQUAL(sizeof(uint16_t), ticket_nonce_len);

            uint8_t ticket_nonce[sizeof(uint16_t)] = { 0 };
            EXPECT_SUCCESS(s2n_stuffer_read_bytes(&conn->handshake.io, ticket_nonce, ticket_nonce_len));

            uint8_t tickets_sent_array[sizeof(uint16_t)] = { 0 };
            struct s2n_blob blob = { 0 };
            EXPECT_SUCCESS(s2n_blob_init(&blob, tickets_sent_array, sizeof(uint16_t)));
            EXPECT_OK(s2n_generate_ticket_nonce(test_tickets_sent, &blob));
            EXPECT_BYTEARRAY_EQUAL(ticket_nonce, blob.data, ticket_nonce_len);

            uint8_t session_ticket_len = 0;
            EXPECT_SUCCESS(s2n_stuffer_read_uint8(&conn->handshake.io, &session_ticket_len));
            uint8_t size_of_extensions_size = sizeof(uint16_t);
            EXPECT_EQUAL(session_ticket_len, (s2n_stuffer_data_available(&conn->handshake.io) - size_of_extensions_size));

            /* Skipping encrypted ticket data */
            EXPECT_SUCCESS(s2n_stuffer_skip_read(&conn->handshake.io, session_ticket_len));

            uint16_t extensions_len = 0;
            EXPECT_SUCCESS(s2n_stuffer_read_uint16(&conn->handshake.io, &extensions_len));
            EXPECT_EQUAL(extensions_len, 0);

            EXPECT_TRUE(conn->tickets_sent == test_tickets_sent + 1);

            EXPECT_SUCCESS(s2n_connection_free(conn));
            EXPECT_SUCCESS(s2n_config_free(config));
        }

        /* tickets_sent overflow */
        {
            struct s2n_config *config;
            uint64_t current_time;
            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));
            EXPECT_NOT_NULL(config = s2n_config_new());
            conn->actual_protocol_version = S2N_TLS13;
            conn->secure.cipher_suite = &s2n_tls13_aes_256_gcm_sha384;
            conn->tickets_sent = UINT16_MAX;

            /* Set up encryption key */
            EXPECT_SUCCESS(s2n_config_set_session_tickets_onoff(config, 1));
            EXPECT_SUCCESS(config->wall_clock(config->sys_clock_ctx, &current_time));
            EXPECT_SUCCESS(s2n_config_add_ticket_crypto_key(config, ticket_key_name, strlen((char *)ticket_key_name),
                         ticket_key.data, sizeof(ticket_key), current_time/ONE_SEC_IN_NANOS));

            EXPECT_SUCCESS(s2n_connection_set_config(conn, config));

            /* Set up master resumption secret */
            struct s2n_blob secret = { 0 };
            struct s2n_stuffer secret_stuffer = { 0 };
            EXPECT_SUCCESS(s2n_blob_init(&secret, conn->secure.master_secret, S2N_TLS_SECRET_LEN));
            EXPECT_SUCCESS(s2n_stuffer_init(&secret_stuffer, &secret));
            EXPECT_SUCCESS(s2n_stuffer_write_bytes(&secret_stuffer, test_master_secret.data, S2N_TLS_SECRET_LEN));

            EXPECT_FAILURE_WITH_ERRNO(s2n_tls13_server_nst_send(conn), S2N_ERR_INTEGER_OVERFLOW);

            EXPECT_SUCCESS(s2n_connection_free(conn));
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

        /* Test: Both session state and decrypt key have longer lifetimes than a week */
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
            EXPECT_SUCCESS(s2n_blob_init(&blob, test_cases[i].value, sizeof(sizeof(test_cases[i].value))));
            EXPECT_OK(s2n_generate_ticket_age_add(&blob, &output));

            EXPECT_EQUAL(output, test_cases[i].expected_output);
        }
    }
}
