/*
 * Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

#include <sys/wait.h>
#include <unistd.h>
#include <stdint.h>
#include <fcntl.h>
#include <errno.h>

#include <s2n.h>

#include "tls/s2n_tls.h"
#include "tls/s2n_connection.h"
#include "tls/s2n_handshake.h"
#include "tls/s2n_tls_parameters.h"


#define ZERO_TO_THIRTY_ONE  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, \
                            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F


int main(int argc, char **argv)
{
    char *cert_chain;
    char *private_key;
    BEGIN_TEST();

    EXPECT_NOT_NULL(cert_chain = malloc(S2N_MAX_TEST_PEM_SIZE));
    EXPECT_NOT_NULL(private_key = malloc(S2N_MAX_TEST_PEM_SIZE));
    EXPECT_SUCCESS(setenv("S2N_DONT_MLOCK", "1", 0));

    /* Success: server sends an empty initial renegotiation_info */
    {
        struct s2n_connection *client_conn;
        struct s2n_config *client_config;
        s2n_blocked_status client_blocked;
        int server_to_client[2];
        int client_to_server[2];

        uint8_t server_extensions[] = {
            /* Extension type TLS_EXTENSION_RENEGOTIATION_INFO */
            0xff, 0x01,
            /* Extension size */
            0x00, 0x01,
            /* renegotiated_connection len */
            0x00,
        };
        int server_extensions_len = sizeof(server_extensions);
        uint8_t server_hello_message[] = {
            /* Protocol version TLS 1.2 */
            0x03, 0x03,
            /* Server random */
            ZERO_TO_THIRTY_ONE,
            /* SessionID len - 32 bytes */
            0x20,
            /* Session ID */
            ZERO_TO_THIRTY_ONE,
            /* Cipher suite - TLS_RSA_WITH_AES_128_CBC_SHA256 */
            0x00, 0x3C,
            /* Compression method - none */
            0x00,
            /* Extensions len */
            (server_extensions_len >> 8) & 0xff, (server_extensions_len & 0xff),
        };
        int body_len = sizeof(server_hello_message) + server_extensions_len;
        uint8_t message_header[] = {
            /* Handshake message type SERVER HELLO */
            0x02,
            /* Body len */
            (body_len >> 16) & 0xff, (body_len >> 8) & 0xff, (body_len & 0xff),
        };
        int message_len = sizeof(message_header) + body_len;
        uint8_t record_header[] = {
            /* Record type HANDSHAKE */
            0x16,
            /* Protocol version TLS 1.2 */
            0x03, 0x03,
            /* Message len */
            (message_len >> 8) & 0xff, (message_len & 0xff),
        };

        /* Create nonblocking pipes */
        EXPECT_SUCCESS(pipe(server_to_client));
        EXPECT_SUCCESS(pipe(client_to_server));
        for (int i = 0; i < 2; i++) {
            EXPECT_NOT_EQUAL(fcntl(server_to_client[i], F_SETFL, fcntl(server_to_client[i], F_GETFL) | O_NONBLOCK), -1);
            EXPECT_NOT_EQUAL(fcntl(client_to_server[i], F_SETFL, fcntl(client_to_server[i], F_GETFL) | O_NONBLOCK), -1);
        }

        EXPECT_NOT_NULL(client_conn = s2n_connection_new(S2N_CLIENT));
        EXPECT_SUCCESS(s2n_connection_set_read_fd(client_conn, server_to_client[0]));
        EXPECT_SUCCESS(s2n_connection_set_write_fd(client_conn, client_to_server[1]));

        EXPECT_NOT_NULL(client_config = s2n_config_new());
        EXPECT_SUCCESS(s2n_connection_set_config(client_conn, client_config));

        /* Send the client hello */
        EXPECT_EQUAL(s2n_negotiate(client_conn, &client_blocked), -1);
        EXPECT_EQUAL(s2n_errno, S2N_ERR_BLOCKED);
        EXPECT_EQUAL(client_blocked, S2N_BLOCKED_ON_READ);

        /* Write the server hello */
        EXPECT_EQUAL(write(server_to_client[1], record_header, sizeof(record_header)), sizeof(record_header));
        EXPECT_EQUAL(write(server_to_client[1], message_header, sizeof(message_header)), sizeof(message_header));
        EXPECT_EQUAL(write(server_to_client[1], server_hello_message, sizeof(server_hello_message)), sizeof(server_hello_message));
        EXPECT_EQUAL(write(server_to_client[1], server_extensions, sizeof(server_extensions)), sizeof(server_extensions));

        /* Verify that we proceed with handshake */
        EXPECT_EQUAL(s2n_negotiate(client_conn, &client_blocked), -1);
        EXPECT_EQUAL(s2n_errno, S2N_ERR_BLOCKED);
        EXPECT_EQUAL(client_blocked, S2N_BLOCKED_ON_READ);

        /* Secure renegotiation is set */
        EXPECT_EQUAL(client_conn->secure_renegotiation, 1);

        EXPECT_SUCCESS(s2n_connection_free(client_conn));

        EXPECT_SUCCESS(s2n_config_free(client_config));

        for (int i = 0; i < 2; i++) {
            EXPECT_SUCCESS(close(server_to_client[i]));
            EXPECT_SUCCESS(close(client_to_server[i]));
        }
    }

    /* Success: server doesn't send an renegotiation_info extension */
    {
        struct s2n_connection *client_conn;
        struct s2n_config *client_config;
        s2n_blocked_status client_blocked;
        int server_to_client[2];
        int client_to_server[2];

        uint8_t server_hello_message[] = {
            /* Protocol version TLS 1.2 */
            0x03, 0x03,
            /* Server random */
            ZERO_TO_THIRTY_ONE,
            /* SessionID len - 32 bytes */
            0x20,
            /* Session ID */
            ZERO_TO_THIRTY_ONE,
            /* Cipher suite - TLS_RSA_WITH_AES_128_CBC_SHA256 */
            0x00, 0x3C,
            /* Compression method - none */
            0x00,
            /* Extensions len */
            0x00, 0x00
        };
        int body_len = sizeof(server_hello_message);
        uint8_t message_header[] = {
            /* Handshake message type SERVER HELLO */
            0x02,
            /* Body len */
            (body_len >> 16) & 0xff, (body_len >> 8) & 0xff, (body_len & 0xff),
        };
        int message_len = sizeof(message_header) + body_len;
        uint8_t record_header[] = {
            /* Record type HANDSHAKE */
            0x16,
            /* Protocol version TLS 1.2 */
            0x03, 0x03,
            /* Message len */
            (message_len >> 8) & 0xff, (message_len & 0xff),
        };

        /* Create nonblocking pipes */
        EXPECT_SUCCESS(pipe(server_to_client));
        EXPECT_SUCCESS(pipe(client_to_server));
        for (int i = 0; i < 2; i++) {
            EXPECT_NOT_EQUAL(fcntl(server_to_client[i], F_SETFL, fcntl(server_to_client[i], F_GETFL) | O_NONBLOCK), -1);
            EXPECT_NOT_EQUAL(fcntl(client_to_server[i], F_SETFL, fcntl(client_to_server[i], F_GETFL) | O_NONBLOCK), -1);
        }

        EXPECT_NOT_NULL(client_conn = s2n_connection_new(S2N_CLIENT));
        EXPECT_SUCCESS(s2n_connection_set_read_fd(client_conn, server_to_client[0]));
        EXPECT_SUCCESS(s2n_connection_set_write_fd(client_conn, client_to_server[1]));

        EXPECT_NOT_NULL(client_config = s2n_config_new());
        EXPECT_SUCCESS(s2n_connection_set_config(client_conn, client_config));

        /* Send the client hello */
        EXPECT_EQUAL(s2n_negotiate(client_conn, &client_blocked), -1);
        EXPECT_EQUAL(s2n_errno, S2N_ERR_BLOCKED);
        EXPECT_EQUAL(client_blocked, S2N_BLOCKED_ON_READ);

        /* Write the server hello */
        EXPECT_EQUAL(write(server_to_client[1], record_header, sizeof(record_header)), sizeof(record_header));
        EXPECT_EQUAL(write(server_to_client[1], message_header, sizeof(message_header)), sizeof(message_header));
        EXPECT_EQUAL(write(server_to_client[1], server_hello_message, sizeof(server_hello_message)), sizeof(server_hello_message));

        /* Verify that we proceed with handshake */
        EXPECT_EQUAL(s2n_negotiate(client_conn, &client_blocked), -1);
        EXPECT_EQUAL(s2n_errno, S2N_ERR_BLOCKED);
        EXPECT_EQUAL(client_blocked, S2N_BLOCKED_ON_READ);

        /* Secure renegotiation is not set, as server doesn't support it */
        EXPECT_EQUAL(client_conn->secure_renegotiation, 0);

        EXPECT_SUCCESS(s2n_connection_free(client_conn));

        EXPECT_SUCCESS(s2n_config_free(client_config));

        for (int i = 0; i < 2; i++) {
            EXPECT_SUCCESS(close(server_to_client[i]));
            EXPECT_SUCCESS(close(client_to_server[i]));
        }
    }

    /* Failure: server sends a non-empty initial renegotiation_info */
    {
        struct s2n_connection *client_conn;
        struct s2n_config *client_config;
        s2n_blocked_status client_blocked;
        int server_to_client[2];
        int client_to_server[2];

        uint8_t server_extensions[] = {
            /* Extension type TLS_EXTENSION_RENEGOTIATION_INFO */
            0xff, 0x01,
            /* Extension size */
            0x00, 0x21,
            /* renegotiated_connection len */
            0x20,
            /* fake renegotiated_connection */
            ZERO_TO_THIRTY_ONE,
        };
        int server_extensions_len = sizeof(server_extensions);
        uint8_t server_hello_message[] = {
            /* Protocol version TLS 1.2 */
            0x03, 0x03,
            /* Server random */
            ZERO_TO_THIRTY_ONE,
            /* SessionID len - 32 bytes */
            0x20,
            /* Session ID */
            ZERO_TO_THIRTY_ONE,
            /* Cipher suite - TLS_RSA_WITH_AES_128_CBC_SHA256 */
            0x00, 0x3C,
            /* Compression method - none */
            0x00,
            /* Extensions len */
            (server_extensions_len >> 8) & 0xff, (server_extensions_len & 0xff),
        };
        int body_len = sizeof(server_hello_message) + server_extensions_len;
        uint8_t message_header[] = {
            /* Handshake message type SERVER HELLO */
            0x02,
            /* Body len */
            (body_len >> 16) & 0xff, (body_len >> 8) & 0xff, (body_len & 0xff),
        };
        int message_len = sizeof(message_header) + body_len;
        uint8_t record_header[] = {
            /* Record type HANDSHAKE */
            0x16,
            /* Protocol version TLS 1.2 */
            0x03, 0x03,
            /* Message len */
            (message_len >> 8) & 0xff, (message_len & 0xff),
        };

        /* Create nonblocking pipes */
        EXPECT_SUCCESS(pipe(server_to_client));
        EXPECT_SUCCESS(pipe(client_to_server));
        for (int i = 0; i < 2; i++) {
            EXPECT_NOT_EQUAL(fcntl(server_to_client[i], F_SETFL, fcntl(server_to_client[i], F_GETFL) | O_NONBLOCK), -1);
            EXPECT_NOT_EQUAL(fcntl(client_to_server[i], F_SETFL, fcntl(client_to_server[i], F_GETFL) | O_NONBLOCK), -1);
        }

        EXPECT_NOT_NULL(client_conn = s2n_connection_new(S2N_CLIENT));
        EXPECT_SUCCESS(s2n_connection_set_read_fd(client_conn, server_to_client[0]));
        EXPECT_SUCCESS(s2n_connection_set_write_fd(client_conn, client_to_server[1]));

        EXPECT_NOT_NULL(client_config = s2n_config_new());
        EXPECT_SUCCESS(s2n_connection_set_config(client_conn, client_config));

        /* Send the client hello */
        EXPECT_EQUAL(s2n_negotiate(client_conn, &client_blocked), -1);
        EXPECT_EQUAL(s2n_errno, S2N_ERR_BLOCKED);
        EXPECT_EQUAL(client_blocked, S2N_BLOCKED_ON_READ);

        /* Write the server hello */
        EXPECT_EQUAL(write(server_to_client[1], record_header, sizeof(record_header)), sizeof(record_header));
        EXPECT_EQUAL(write(server_to_client[1], message_header, sizeof(message_header)), sizeof(message_header));
        EXPECT_EQUAL(write(server_to_client[1], server_hello_message, sizeof(server_hello_message)), sizeof(server_hello_message));
        EXPECT_EQUAL(write(server_to_client[1], server_extensions, sizeof(server_extensions)), sizeof(server_extensions));

        /* Verify that we fail for non-empty renegotiated_connection */
        EXPECT_SUCCESS(s2n_connection_set_blinding(client_conn, S2N_SELF_SERVICE_BLINDING));
        EXPECT_EQUAL(s2n_negotiate(client_conn, &client_blocked), -1);
        EXPECT_EQUAL(s2n_errno, S2N_ERR_NON_EMPTY_RENEGOTIATION_INFO);

        EXPECT_SUCCESS(s2n_connection_free(client_conn));

        EXPECT_SUCCESS(s2n_config_free(client_config));

        for (int i = 0; i < 2; i++) {
            EXPECT_SUCCESS(close(server_to_client[i]));
            EXPECT_SUCCESS(close(client_to_server[i]));
        }
    }

    free(cert_chain);
    free(private_key);
    END_TEST();
    return 0;
}

