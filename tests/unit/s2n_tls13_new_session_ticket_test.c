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

#include <s2n.h>

#include "tls/s2n_connection.h"
#include "tls/s2n_tls13.h"
#include "tls/s2n_record.h"
#include "tls/s2n_post_handshake.h"
#include "tls/s2n_tls13_handshake.h"

#define MAX_TEST_SESSION_SIZE 300

uint8_t session_ticket_counter = 0;
static int s2n_test_session_ticket_cb(struct s2n_connection *conn, struct s2n_session_ticket *ticket)
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

static int s2n_test_init_encryption(struct s2n_connection *conn)
{
    POSIX_ENSURE_REF(conn);

    
    struct s2n_cipher_suite *cipher_suite = &s2n_tls13_aes_128_gcm_sha256;
    conn->server->cipher_suite = cipher_suite;
    conn->client->cipher_suite = cipher_suite;
    conn->secure.cipher_suite = &s2n_tls13_aes_128_gcm_sha256;

    conn->actual_protocol_version = S2N_TLS13;

    /**
     *= https://tools.ietf.org/rfc/rfc8448#section-3
     *#      PRK (32 octets):  a1 1a f9 f0 55 31 f8 56 ad 47 11 6b 45 a9 50 32
     *#  82 04 b4 f4 4b fb 6b 3a 4b 4f 1f 3f cb 63 16 43
     */
    S2N_BLOB_FROM_HEX(application_secret,
    "a1 1a f9 f0 55 31 f8 56 ad 47 11 6b 45 a9 50 32 \
         82 04 b4 f4 4b fb 6b 3a 4b 4f 1f 3f cb 63 16 43"); 

    /**
     *= https://tools.ietf.org/rfc/rfc8448#section-3
     *#      key expanded (16 octets):  9f 02 28 3b 6c 9c 07 ef c2 6b b9 f2 ac
     *#  92 e3 56
     */
    S2N_BLOB_FROM_HEX(key, "9f 02 28 3b 6c 9c 07 ef c2 6b b9 f2 ac \
         92 e3 56");
    
    /**
     *= https://tools.ietf.org/rfc/rfc8448#section-3
     *#     iv expanded (12 octets):  cf 78 2b 88 dd 83 54 9a ad f1 e9 84
     */
    S2N_BLOB_FROM_HEX(iv, "cf 78 2b 88 dd 83 54 9a ad f1 e9 84");

    /* Initialize application secrets */
    POSIX_CHECKED_MEMCPY(conn->secure.server_app_secret, application_secret.data, application_secret.size);
    POSIX_CHECKED_MEMCPY(conn->secure.client_app_secret, application_secret.data, application_secret.size);

    struct s2n_session_key *server_session_key = &conn->server->server_key;
    struct s2n_session_key *client_session_key = &conn->server->server_key;
    uint8_t *server_implicit_iv = conn->server->server_implicit_iv;
    uint8_t *client_implicit_iv = conn->client->client_implicit_iv;
 
    /* Initialize record algorithm */
    POSIX_GUARD(cipher_suite->record_alg->cipher->init(server_session_key));
    POSIX_GUARD(cipher_suite->record_alg->cipher->init(client_session_key));
    POSIX_GUARD(cipher_suite->record_alg->cipher->set_encryption_key(server_session_key, &key));
    POSIX_GUARD(cipher_suite->record_alg->cipher->set_encryption_key(client_session_key, &key));
    POSIX_GUARD(cipher_suite->record_alg->cipher->set_decryption_key(server_session_key, &key));
    POSIX_GUARD(cipher_suite->record_alg->cipher->set_decryption_key(client_session_key, &key));

    /* Initialized secrets */
    POSIX_CHECKED_MEMCPY(conn->secure.server_app_secret, application_secret.data, application_secret.size);
    POSIX_CHECKED_MEMCPY(conn->secure.client_app_secret, application_secret.data, application_secret.size);
 
    /* Copy iv bytes from input data */
    POSIX_CHECKED_MEMCPY(server_implicit_iv, iv.data, iv.size);
    POSIX_CHECKED_MEMCPY(client_implicit_iv, iv.data, iv.size);

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
    uint64_t current_time;
    uint8_t ticket_key_name[16] = "2016.07.26.15\0";
    EXPECT_SUCCESS(config->wall_clock(config->sys_clock_ctx, &current_time));
    EXPECT_SUCCESS(s2n_config_add_ticket_crypto_key(config, ticket_key_name, strlen((char *)ticket_key_name),
                    ticket_key.data, ticket_key.size, current_time/ONE_SEC_IN_NANOS));

    return S2N_SUCCESS;
}

int main(int argc, char **argv)
{   
    BEGIN_TEST();
    
    /* s2n_send sends NewSessionTicket message */
    {
        struct s2n_connection *server_conn= s2n_connection_new(S2N_SERVER);
        struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT);
        EXPECT_NOT_NULL(server_conn);
        EXPECT_NOT_NULL(client_conn);

        struct s2n_config *config = s2n_config_new();
        EXPECT_NOT_NULL(config);

        EXPECT_SUCCESS(s2n_config_set_session_tickets_onoff(config, 1));
        EXPECT_SUCCESS(s2n_setup_test_ticket_key(config));
        EXPECT_SUCCESS(s2n_config_set_session_ticket_cb(config, s2n_test_session_ticket_cb, NULL));
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, config));
        EXPECT_SUCCESS(s2n_connection_set_config(client_conn, config));

        EXPECT_SUCCESS(s2n_test_init_encryption(server_conn));
        EXPECT_SUCCESS(s2n_test_init_encryption(client_conn));

        DEFER_CLEANUP(struct s2n_stuffer input, s2n_stuffer_free);
        DEFER_CLEANUP(struct s2n_stuffer output, s2n_stuffer_free);
        EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&input, 0));
        EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&output, 0));
                                        
        EXPECT_SUCCESS(s2n_connection_set_io_stuffers(&input, &output, server_conn));
        EXPECT_SUCCESS(s2n_connection_set_io_stuffers(&output, &input, client_conn));

        /* Create conditions to send NewSessionTicket message */
        uint8_t tickets_to_send = 5;
        server_conn->tickets_to_send = tickets_to_send;

        /* Next message to send will trigger a NewSessionTicket message*/
        s2n_blocked_status blocked;
        char message[] = "sent message";
        EXPECT_SUCCESS(s2n_send(server_conn, message, sizeof(message), &blocked));

        /* Receive NewSessionTicket message */
        uint8_t data[100];
        EXPECT_SUCCESS(s2n_recv(client_conn, data, sizeof(data), &blocked));

        EXPECT_EQUAL(session_ticket_counter, tickets_to_send);

        EXPECT_SUCCESS(s2n_config_free(config));
        EXPECT_SUCCESS(s2n_connection_free(server_conn));
        EXPECT_SUCCESS(s2n_connection_free(client_conn));
    }
}
