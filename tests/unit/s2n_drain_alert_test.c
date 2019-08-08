/*
 * Copyright 2017 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

#include <unistd.h>
#include <stdint.h>

#include <s2n.h>

#define ZERO_TO_THIRTY_ONE  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, \
                            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F

#define INTERNAL_ERROR_ALERT_HEX 0x50

/* This test simulates a client sends a TLS alert record and closes its socket immediately after the ClientHello.
 * We want to validate that s2n informs the caller of the alert instead of an I/O error. Both errors result
 * in a failed handshake, but the alert is generally more useful.
 */

int main(int argc, char **argv)
{
    BEGIN_TEST();
    uint8_t client_hello_message[] = {
        /* Protocol version TLS 1.2 */
        0x03, 0x03,
        /* Client random */
        ZERO_TO_THIRTY_ONE,
        /* SessionID len - 32 bytes */
        0x20,
        /* Session ID */
        ZERO_TO_THIRTY_ONE,
        /* Cipher suites len */
        0x00, 0x02,
        /* Cipher suite - TLS_RSA_WITH_AES_128_CBC_SHA256 */
        0x00, 0x3C,
        /* Compression methods len */
        0x01,
        /* Compression method - none */
        0x00,
        /* Extensions len */
        0x00, 0x00
    };
    size_t body_len = sizeof(client_hello_message);
    uint8_t message_header[] = {
        /* Handshake message type CLIENT HELLO */
        0x01,
        /* Body len */
        (body_len >> 16) & 0xff, (body_len >> 8) & 0xff, (body_len & 0xff),
    };
    size_t message_len = sizeof(message_header) + body_len;
    uint8_t record_header[] = {
        /* Record type HANDSHAKE */
        0x16,
        /* Protocol version TLS 1.2 */
        0x03, 0x03,
        /* Message len */
        (message_len >> 8) & 0xff, (message_len & 0xff),
    };

    uint8_t alert_record[] = {
        /* Record type ALERT */
        0x15,
        /* Protocol version TLS 1.2 */
        0x03, 0x03,
        /* Length */
        0x00, 0x02,
        /* Fatal alert "internal_error" */
        0x02, INTERNAL_ERROR_ALERT_HEX,
    };

    struct s2n_connection *server_conn;
    struct s2n_config *server_config;
    s2n_blocked_status server_blocked;
    int server_to_client[2];
    int client_to_server[2];
    char *cert_chain = malloc(S2N_MAX_TEST_PEM_SIZE);
    char *private_key = malloc(S2N_MAX_TEST_PEM_SIZE);
    struct s2n_cert_chain_and_key *chain_and_key;

    signal(SIGPIPE, SIG_IGN);
    EXPECT_SUCCESS(pipe(server_to_client));
    EXPECT_SUCCESS(pipe(client_to_server));

    EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));
    EXPECT_SUCCESS(s2n_connection_set_read_fd(server_conn, client_to_server[0]));
    EXPECT_SUCCESS(s2n_connection_set_write_fd(server_conn, server_to_client[1]));

    EXPECT_NOT_NULL(server_config = s2n_config_new());
    EXPECT_SUCCESS(s2n_read_test_pem(S2N_DEFAULT_TEST_CERT_CHAIN, cert_chain, S2N_MAX_TEST_PEM_SIZE));
    EXPECT_SUCCESS(s2n_read_test_pem(S2N_DEFAULT_TEST_PRIVATE_KEY, private_key, S2N_MAX_TEST_PEM_SIZE));
    EXPECT_NOT_NULL(chain_and_key = s2n_cert_chain_and_key_new());
    EXPECT_SUCCESS(s2n_cert_chain_and_key_load_pem(chain_and_key, cert_chain, private_key));
    EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(server_config, chain_and_key));
    EXPECT_SUCCESS(s2n_connection_set_config(server_conn, server_config));

    /* Send the client hello */
    EXPECT_EQUAL(write(client_to_server[1], record_header, sizeof(record_header)), sizeof(record_header));
    EXPECT_EQUAL(write(client_to_server[1], message_header, sizeof(message_header)), sizeof(message_header));
    EXPECT_EQUAL(write(client_to_server[1], client_hello_message, sizeof(client_hello_message)), sizeof(client_hello_message));

    /* Send an alert from client to server */
    EXPECT_EQUAL(write(client_to_server[1], alert_record, sizeof(alert_record)), sizeof(alert_record));

    /* Close the client read/write end */
    EXPECT_SUCCESS(close(server_to_client[0]));
    EXPECT_SUCCESS(close(client_to_server[1]));

    /* Expect the server to fail due to an incoming alert. We should not fail due to an I/O error(EPIPE). */
    s2n_negotiate(server_conn, &server_blocked);
    EXPECT_EQUAL(s2n_error_get_type(s2n_errno), S2N_ERR_T_ALERT);
    EXPECT_EQUAL(s2n_connection_get_alert(server_conn), INTERNAL_ERROR_ALERT_HEX);

    EXPECT_SUCCESS(s2n_connection_free(server_conn));
    EXPECT_SUCCESS(s2n_cert_chain_and_key_free(chain_and_key));
    EXPECT_SUCCESS(s2n_config_free(server_config));
    free(cert_chain);
    free(private_key);

    EXPECT_SUCCESS(close(server_to_client[1]));
    EXPECT_SUCCESS(close(client_to_server[0]));

    END_TEST();
}
