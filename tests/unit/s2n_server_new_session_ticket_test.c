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

int main(int argc, char **argv)
{
    BEGIN_TEST();
    
    /* s2n_tls13_server_nst_send */
    {
        /* Check session ticket message is correctly written. The contents of the 
         * message will be tested more thoroughly once the s2n_tls13_server_nst_recv 
         * function is written. */
        {
            /* Session ticket keys. Taken from test vectors in https://tools.ietf.org/html/rfc5869 */
            uint8_t ticket_key_name[16] = "2016.07.26.15\0";
            S2N_BLOB_FROM_HEX(ticket_key, 
            "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5");

            S2N_BLOB_FROM_HEX(test_master_secret,
            "ee85dd54781bd4d8a100589a9fe6ac9a3797b811e977f549cd"
            "531be2441d7c63e2b9729d145c11d84af35957727565a4");

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

            /* The TLS1.3 new session ticket message size cannot be tested here
             * because the session resumption ticket secret varies from 28-48 bytes. */
            EXPECT_SUCCESS(s2n_stuffer_skip_read(&conn->handshake.io, SIZEOF_UINT24));

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
            uint8_t tickets_sent_array[sizeof(uint16_t)] = { 0 };
            struct s2n_blob blob = { 0 };
            EXPECT_SUCCESS(s2n_blob_init(&blob, tickets_sent_array, sizeof(uint16_t)));
            EXPECT_SUCCESS(s2n_stuffer_read_bytes(&conn->handshake.io, ticket_nonce, ticket_nonce_len));
            EXPECT_OK(s2n_generate_ticket_nonce(test_tickets_sent, &blob));
            EXPECT_BYTEARRAY_EQUAL(ticket_nonce, tickets_sent_array, ticket_nonce_len);

            /* The TLS1.3 session ticket length cannot be tested here
             * because the session resumption ticket secret varies from 28-48 bytes. */
            uint8_t session_ticket_len = 0;
            EXPECT_SUCCESS(s2n_stuffer_read_uint8(&conn->handshake.io, &session_ticket_len));

            /* Skipping encrypted ticket data */
            EXPECT_SUCCESS(s2n_stuffer_skip_read(&conn->handshake.io, session_ticket_len));

            uint16_t extensions_len = 0;
            EXPECT_SUCCESS(s2n_stuffer_read_uint16(&conn->handshake.io, &extensions_len));
            EXPECT_EQUAL(extensions_len, 0);

            EXPECT_TRUE(conn->tickets_sent == test_tickets_sent + 1);

            EXPECT_SUCCESS(s2n_connection_free(conn));
            EXPECT_SUCCESS(s2n_config_free(config));
        }
    }

    /* s2n_generate_ticket_nonce */
    {
        /* Maximum value can be converted */
        {
            uint16_t test_value = UINT16_MAX;
            uint8_t data[sizeof(uint16_t)] = { 0 };
            struct s2n_blob blob = { 0 };
            EXPECT_SUCCESS(s2n_blob_init(&blob, data, sizeof(data)));
            EXPECT_OK(s2n_generate_ticket_nonce(test_value, &blob));

            EXPECT_EQUAL(data[0], UINT8_MAX);
            EXPECT_EQUAL(data[1], UINT8_MAX);
        }

        /* Random value can be converted */
        {
            uint16_t test_value = UINT8_MAX;
            uint8_t data[sizeof(uint16_t)] = { 0 };
            struct s2n_blob blob = { 0 };
            EXPECT_SUCCESS(s2n_blob_init(&blob, data, sizeof(data)));
            EXPECT_OK(s2n_generate_ticket_nonce(test_value, &blob));

            EXPECT_EQUAL(data[0], 0);
            EXPECT_EQUAL(data[1], UINT8_MAX);
        }

    }

    /* s2n_generate_ticket_age_add */
    {
        /* Maximum value can be converted */
        {
            uint8_t data[] = { UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX};
            uint32_t ticket_age_add = 0;
            struct s2n_blob blob = { 0 };
            EXPECT_SUCCESS(s2n_blob_init(&blob, data, sizeof(data)));
            EXPECT_OK(s2n_generate_ticket_age_add(&blob, &ticket_age_add));

            EXPECT_EQUAL(ticket_age_add, UINT32_MAX);
        }

        /* Random value can be converted */
        {
            uint8_t data[] = { 0, 0, UINT8_MAX, UINT8_MAX};
            uint32_t ticket_age_add = 0;
            struct s2n_blob blob = { 0 };
            EXPECT_SUCCESS(s2n_blob_init(&blob, data, sizeof(data)));
            EXPECT_OK(s2n_generate_ticket_age_add(&blob, &ticket_age_add));

            EXPECT_EQUAL(ticket_age_add, UINT16_MAX);
        }
    }
}
