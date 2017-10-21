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


/* This data format is bogus, but sufficient to test the server is able
   to return correctly what has been configured.  Once the client does
   validation we will need real data here.
 */
static uint8_t sct_list[] = {
    0xff, 0xff, 0xff, 0xff, 0xff
};

extern message_type_t s2n_conn_get_current_message_type(struct s2n_connection *conn);

int main(int argc, char **argv)
{
    char *cert_chain;
    char *private_key;
    BEGIN_TEST();

    EXPECT_NOT_NULL(cert_chain = malloc(S2N_MAX_TEST_PEM_SIZE));
    EXPECT_NOT_NULL(private_key = malloc(S2N_MAX_TEST_PEM_SIZE));
    EXPECT_SUCCESS(setenv("S2N_ENABLE_CLIENT_MODE", "1", 0));
    EXPECT_SUCCESS(setenv("S2N_DONT_MLOCK", "1", 0));

    /* Client doesn't use the server name extension. */
    {
        struct s2n_connection *client_conn;
        struct s2n_connection *server_conn;
        struct s2n_config *server_config;
        int server_to_client[2];
        int client_to_server[2];

        /* Create nonblocking pipes */
        EXPECT_SUCCESS(pipe(server_to_client));
        EXPECT_SUCCESS(pipe(client_to_server));
        for (int i = 0; i < 2; i++) {
           EXPECT_NOT_EQUAL(fcntl(server_to_client[i], F_SETFL, fcntl(server_to_client[i], F_GETFL) | O_NONBLOCK), -1);
           EXPECT_NOT_EQUAL(fcntl(client_to_server[i], F_SETFL, fcntl(client_to_server[i], F_GETFL) | O_NONBLOCK), -1);
        }

        struct s2n_config *client_config;
        EXPECT_NOT_NULL(client_config = s2n_config_new());
        EXPECT_NOT_NULL(client_conn = s2n_connection_new(S2N_CLIENT));
        client_conn->actual_protocol_version = S2N_TLS12;
        client_conn->server_protocol_version = S2N_TLS12;
        client_conn->client_protocol_version = S2N_TLS12;

        EXPECT_SUCCESS(s2n_connection_set_read_fd(client_conn, server_to_client[0]));
        EXPECT_SUCCESS(s2n_connection_set_write_fd(client_conn, client_to_server[1]));

        EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));
        server_conn->actual_protocol_version = S2N_TLS12;
        server_conn->server_protocol_version = S2N_TLS12;
        server_conn->client_protocol_version = S2N_TLS12;
        EXPECT_SUCCESS(s2n_connection_set_read_fd(server_conn, client_to_server[0]));
        EXPECT_SUCCESS(s2n_connection_set_write_fd(server_conn, server_to_client[1]));


        EXPECT_NOT_NULL(server_config = s2n_config_new());
        EXPECT_SUCCESS(s2n_read_test_pem(S2N_DEFAULT_TEST_CERT_CHAIN, cert_chain, S2N_MAX_TEST_PEM_SIZE));
        EXPECT_SUCCESS(s2n_read_test_pem(S2N_DEFAULT_TEST_PRIVATE_KEY, private_key, S2N_MAX_TEST_PEM_SIZE));
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key(server_config, cert_chain, private_key));
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, server_config));

        EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));

        /* Verify that the server didn't receive the server name. */
        EXPECT_NULL(s2n_get_server_name(server_conn));

        EXPECT_SUCCESS(s2n_shutdown_test_server_and_client(server_conn, client_conn));

        EXPECT_SUCCESS(s2n_connection_free(server_conn));
        EXPECT_SUCCESS(s2n_connection_free(client_conn));

        EXPECT_SUCCESS(s2n_config_free(server_config));

        for (int i = 0; i < 2; i++) {
           EXPECT_SUCCESS(close(server_to_client[i]));
           EXPECT_SUCCESS(close(client_to_server[i]));
        }
    }

    /* Client uses the server name extension. */
    {
        struct s2n_connection *client_conn;
        struct s2n_connection *server_conn;
        struct s2n_config *server_config;
        int server_to_client[2];
        int client_to_server[2];

        const char *sent_server_name = "awesome.amazonaws.com";
        const char *received_server_name;

        /* Create nonblocking pipes */
        EXPECT_SUCCESS(pipe(server_to_client));
        EXPECT_SUCCESS(pipe(client_to_server));
        for (int i = 0; i < 2; i++) {
            EXPECT_NOT_EQUAL(fcntl(server_to_client[i], F_SETFL, fcntl(server_to_client[i], F_GETFL) | O_NONBLOCK), -1);
            EXPECT_NOT_EQUAL(fcntl(client_to_server[i], F_SETFL, fcntl(client_to_server[i], F_GETFL) | O_NONBLOCK), -1);
        }

        struct s2n_config *client_config;
        EXPECT_NOT_NULL(client_config = s2n_config_new());
        EXPECT_NOT_NULL(client_conn = s2n_connection_new(S2N_CLIENT));
        client_conn->actual_protocol_version = S2N_TLS12;
        client_conn->server_protocol_version = S2N_TLS12;
        client_conn->client_protocol_version = S2N_TLS12;
        EXPECT_SUCCESS(s2n_connection_set_read_fd(client_conn, server_to_client[0]));
        EXPECT_SUCCESS(s2n_connection_set_write_fd(client_conn, client_to_server[1]));

        /* Set the server name */
        EXPECT_SUCCESS(s2n_set_server_name(client_conn, sent_server_name));

        EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));
        server_conn->actual_protocol_version = S2N_TLS12;
        server_conn->server_protocol_version = S2N_TLS12;
        server_conn->client_protocol_version = S2N_TLS12;
        EXPECT_SUCCESS(s2n_connection_set_read_fd(server_conn, client_to_server[0]));
        EXPECT_SUCCESS(s2n_connection_set_write_fd(server_conn, server_to_client[1]));

        EXPECT_NOT_NULL(server_config = s2n_config_new());
        EXPECT_SUCCESS(s2n_read_test_pem(S2N_DEFAULT_TEST_CERT_CHAIN, cert_chain, S2N_MAX_TEST_PEM_SIZE));
        EXPECT_SUCCESS(s2n_read_test_pem(S2N_DEFAULT_TEST_PRIVATE_KEY, private_key, S2N_MAX_TEST_PEM_SIZE));
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key(server_config, cert_chain, private_key));
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, server_config));

        EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));

        /* Verify that the server name was received intact. */
        EXPECT_NOT_NULL(received_server_name = s2n_get_server_name(server_conn));
        EXPECT_EQUAL(strlen(received_server_name), strlen(sent_server_name));
        EXPECT_BYTEARRAY_EQUAL(received_server_name, sent_server_name, strlen(received_server_name));

        EXPECT_SUCCESS(s2n_shutdown_test_server_and_client(server_conn, client_conn));

        EXPECT_SUCCESS(s2n_connection_free(server_conn));
        EXPECT_SUCCESS(s2n_connection_free(client_conn));

        EXPECT_SUCCESS(s2n_config_free(server_config));
        for (int i = 0; i < 2; i++) {
            EXPECT_SUCCESS(close(server_to_client[i]));
            EXPECT_SUCCESS(close(client_to_server[i]));
        }
    }

    /* Client sends multiple server names. */
    {
        struct s2n_connection *server_conn;
        struct s2n_config *server_config;
        s2n_blocked_status server_blocked;
        int server_to_client[2];
        int client_to_server[2];
        const char *sent_server_name = "svr";
        const char *received_server_name;

        uint8_t client_extensions[] = {
            /* Extension type TLS_EXTENSION_SERVER_NAME */
            0x00, 0x00,
            /* Extension size */
            0x00, 0x0C,
            /* All server names len */
            0x00, 0x0A,
            /* First server name type - host name */
            0x00,
            /* First server name len */
            0x00, 0x03,
            /* First server name, matches sent_server_name */
            's', 'v', 'r',
            /* Second server name type - host name */
            0x00,
            /* Second server name len */
            0x00, 0x01,
            /* Second server name */
            0xFF,
        };
        int client_extensions_len = sizeof(client_extensions);
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
            (client_extensions_len >> 8) & 0xff, (client_extensions_len & 0xff),
        };
        int body_len = sizeof(client_hello_message) + client_extensions_len;
        uint8_t message_header[] = {
            /* Handshake message type CLIENT HELLO */
            0x01,
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

        EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));
        server_conn->actual_protocol_version = S2N_TLS12;
        server_conn->server_protocol_version = S2N_TLS12;
        server_conn->client_protocol_version = S2N_TLS12;
        EXPECT_SUCCESS(s2n_connection_set_read_fd(server_conn, client_to_server[0]));
        EXPECT_SUCCESS(s2n_connection_set_write_fd(server_conn, server_to_client[1]));

        EXPECT_NOT_NULL(server_config = s2n_config_new());
        EXPECT_SUCCESS(s2n_read_test_pem(S2N_DEFAULT_TEST_CERT_CHAIN, cert_chain, S2N_MAX_TEST_PEM_SIZE));
        EXPECT_SUCCESS(s2n_read_test_pem(S2N_DEFAULT_TEST_PRIVATE_KEY, private_key, S2N_MAX_TEST_PEM_SIZE));
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key(server_config, cert_chain, private_key));
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, server_config));

        /* Send the client hello */
        EXPECT_EQUAL(write(client_to_server[1], record_header, sizeof(record_header)), sizeof(record_header));
        EXPECT_EQUAL(write(client_to_server[1], message_header, sizeof(message_header)), sizeof(message_header));
        EXPECT_EQUAL(write(client_to_server[1], client_hello_message, sizeof(client_hello_message)), sizeof(client_hello_message));
        EXPECT_EQUAL(write(client_to_server[1], client_extensions, sizeof(client_extensions)), sizeof(client_extensions));

        /* Verify that the CLIENT HELLO is accepted */
        s2n_negotiate(server_conn, &server_blocked);
        EXPECT_TRUE(s2n_conn_get_current_message_type(server_conn) > CLIENT_HELLO);
        EXPECT_EQUAL(server_conn->handshake.handshake_type, NEGOTIATED | FULL_HANDSHAKE);

        /* Verify that the server name was received intact. */
        EXPECT_NOT_NULL(received_server_name = s2n_get_server_name(server_conn));
        EXPECT_EQUAL(strlen(received_server_name), strlen(sent_server_name));
        EXPECT_BYTEARRAY_EQUAL(received_server_name, sent_server_name, strlen(received_server_name));

        /* Not a real tls client but make sure we block on its close_notify */
        int shutdown_rc = s2n_shutdown(server_conn, &server_blocked);
        EXPECT_EQUAL(shutdown_rc, -1);
        EXPECT_EQUAL(errno, EAGAIN);
        EXPECT_EQUAL(server_conn->close_notify_queued, 1);

        EXPECT_SUCCESS(s2n_connection_free(server_conn));

        EXPECT_SUCCESS(s2n_config_free(server_config));
        for (int i = 0; i < 2; i++) {
            EXPECT_SUCCESS(close(server_to_client[i]));
            EXPECT_SUCCESS(close(client_to_server[i]));
        }
    }

    /* Client sends a valid initial renegotiation_info */
    {
        struct s2n_connection *server_conn;
        struct s2n_config *server_config;
        s2n_blocked_status server_blocked;
        int server_to_client[2];
        int client_to_server[2];

        uint8_t client_extensions[] = {
            /* Extension type TLS_EXTENSION_RENEGOTIATION_INFO */
            0xff, 0x01,
            /* Extension size */
            0x00, 0x01,
            /* Empty renegotiated_connection */
            0x00,
        };
        int client_extensions_len = sizeof(client_extensions);
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
            (client_extensions_len >> 8) & 0xff, (client_extensions_len & 0xff),
        };
        int body_len = sizeof(client_hello_message) + client_extensions_len;
        uint8_t message_header[] = {
            /* Handshake message type CLIENT HELLO */
            0x01,
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

        EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));
        EXPECT_SUCCESS(s2n_connection_set_read_fd(server_conn, client_to_server[0]));
        EXPECT_SUCCESS(s2n_connection_set_write_fd(server_conn, server_to_client[1]));

        EXPECT_NOT_NULL(server_config = s2n_config_new());
        EXPECT_SUCCESS(s2n_read_test_pem(S2N_DEFAULT_TEST_CERT_CHAIN, cert_chain, S2N_MAX_TEST_PEM_SIZE));
        EXPECT_SUCCESS(s2n_read_test_pem(S2N_DEFAULT_TEST_PRIVATE_KEY, private_key, S2N_MAX_TEST_PEM_SIZE));
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key(server_config, cert_chain, private_key));
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, server_config));

        /* Send the client hello */
        EXPECT_EQUAL(write(client_to_server[1], record_header, sizeof(record_header)), sizeof(record_header));
        EXPECT_EQUAL(write(client_to_server[1], message_header, sizeof(message_header)), sizeof(message_header));
        EXPECT_EQUAL(write(client_to_server[1], client_hello_message, sizeof(client_hello_message)), sizeof(client_hello_message));
        EXPECT_EQUAL(write(client_to_server[1], client_extensions, sizeof(client_extensions)), sizeof(client_extensions));

        /* Verify that the CLIENT HELLO is accepted */
        s2n_negotiate(server_conn, &server_blocked);
        EXPECT_TRUE(s2n_conn_get_current_message_type(server_conn) > CLIENT_HELLO);
        EXPECT_EQUAL(server_conn->handshake.handshake_type & NEGOTIATED, NEGOTIATED);

        /* Verify that the that we detected secure_renegotiation */
        EXPECT_EQUAL(server_conn->secure_renegotiation, 1);

        /* Not a real tls client but make sure we block on its close_notify */
        int shutdown_rc = s2n_shutdown(server_conn, &server_blocked);
        EXPECT_EQUAL(shutdown_rc, -1);
        EXPECT_EQUAL(errno, EAGAIN);
        EXPECT_EQUAL(server_conn->close_notify_queued, 1);

        EXPECT_SUCCESS(s2n_connection_free(server_conn));

        EXPECT_SUCCESS(s2n_config_free(server_config));
        for (int i = 0; i < 2; i++) {
            EXPECT_SUCCESS(close(server_to_client[i]));
            EXPECT_SUCCESS(close(client_to_server[i]));
        }
    }

    /* Client sends a non-empty initial renegotiation_info */
    {
        struct s2n_connection *server_conn;
        struct s2n_config *server_config;
        s2n_blocked_status server_blocked;
        int server_to_client[2];
        int client_to_server[2];

        uint8_t client_extensions[] = {
            /* Extension type TLS_EXTENSION_RENEGOTIATION_INFO */
            0xff, 0x01,
            /* Extension size */
            0x00, 0x21,
            /* renegotiated_connection len */
            0x20,
            /* fake renegotiated_connection */
            ZERO_TO_THIRTY_ONE,
        };
        int client_extensions_len = sizeof(client_extensions);
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
            (client_extensions_len >> 8) & 0xff, (client_extensions_len & 0xff),
        };
        int body_len = sizeof(client_hello_message) + client_extensions_len;
        uint8_t message_header[] = {
            /* Handshake message type CLIENT HELLO */
            0x01,
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

        EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));
        EXPECT_SUCCESS(s2n_connection_set_read_fd(server_conn, client_to_server[0]));
        EXPECT_SUCCESS(s2n_connection_set_write_fd(server_conn, server_to_client[1]));

        EXPECT_NOT_NULL(server_config = s2n_config_new());
        EXPECT_SUCCESS(s2n_read_test_pem(S2N_DEFAULT_TEST_CERT_CHAIN, cert_chain, S2N_MAX_TEST_PEM_SIZE));
        EXPECT_SUCCESS(s2n_read_test_pem(S2N_DEFAULT_TEST_PRIVATE_KEY, private_key, S2N_MAX_TEST_PEM_SIZE));
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key(server_config, cert_chain, private_key));
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, server_config));

        /* Send the client hello */
        EXPECT_EQUAL(write(client_to_server[1], record_header, sizeof(record_header)), sizeof(record_header));
        EXPECT_EQUAL(write(client_to_server[1], message_header, sizeof(message_header)), sizeof(message_header));
        EXPECT_EQUAL(write(client_to_server[1], client_hello_message, sizeof(client_hello_message)), sizeof(client_hello_message));
        EXPECT_EQUAL(write(client_to_server[1], client_extensions, sizeof(client_extensions)), sizeof(client_extensions));

        /* Verify that we fail for non-empty renegotiated_connection */
        EXPECT_SUCCESS(s2n_connection_set_blinding(server_conn, S2N_SELF_SERVICE_BLINDING));
        s2n_negotiate(server_conn, &server_blocked);
        EXPECT_EQUAL(s2n_errno, S2N_ERR_NON_EMPTY_RENEGOTIATION_INFO);

        EXPECT_SUCCESS(s2n_connection_free(server_conn));

        EXPECT_SUCCESS(s2n_config_free(server_config));
        for (int i = 0; i < 2; i++) {
            EXPECT_SUCCESS(close(server_to_client[i]));
            EXPECT_SUCCESS(close(client_to_server[i]));
        }
    }

    /* Client doesn't use the OCSP extension. */
    {
        struct s2n_connection *client_conn;
        struct s2n_connection *server_conn;
        struct s2n_config *server_config;
        int server_to_client[2];
        int client_to_server[2];
        uint32_t length;

        /* Create nonblocking pipes */
        EXPECT_SUCCESS(pipe(server_to_client));
        EXPECT_SUCCESS(pipe(client_to_server));
        for (int i = 0; i < 2; i++) {
           EXPECT_NOT_EQUAL(fcntl(server_to_client[i], F_SETFL, fcntl(server_to_client[i], F_GETFL) | O_NONBLOCK), -1);
           EXPECT_NOT_EQUAL(fcntl(client_to_server[i], F_SETFL, fcntl(client_to_server[i], F_GETFL) | O_NONBLOCK), -1);
        }

        struct s2n_config *client_config;
        EXPECT_NOT_NULL(client_config = s2n_config_new());
        EXPECT_NOT_NULL(client_conn = s2n_connection_new(S2N_CLIENT));
        client_conn->actual_protocol_version = S2N_TLS12;
        client_conn->server_protocol_version = S2N_TLS12;
        client_conn->client_protocol_version = S2N_TLS12;
        EXPECT_SUCCESS(s2n_connection_set_read_fd(client_conn, server_to_client[0]));
        EXPECT_SUCCESS(s2n_connection_set_write_fd(client_conn, client_to_server[1]));

        EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));
        server_conn->actual_protocol_version = S2N_TLS12;
        server_conn->server_protocol_version = S2N_TLS12;
        server_conn->client_protocol_version = S2N_TLS12;
        EXPECT_SUCCESS(s2n_connection_set_read_fd(server_conn, client_to_server[0]));
        EXPECT_SUCCESS(s2n_connection_set_write_fd(server_conn, server_to_client[1]));

        EXPECT_NOT_NULL(server_config = s2n_config_new());
        EXPECT_SUCCESS(s2n_read_test_pem(S2N_DEFAULT_TEST_CERT_CHAIN, cert_chain, S2N_MAX_TEST_PEM_SIZE));
        EXPECT_SUCCESS(s2n_read_test_pem(S2N_DEFAULT_TEST_PRIVATE_KEY, private_key, S2N_MAX_TEST_PEM_SIZE));
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key(server_config, cert_chain, private_key));
        EXPECT_SUCCESS(s2n_config_set_extension_data(server_config, S2N_EXTENSION_OCSP_STAPLING, server_ocsp_status, sizeof(server_ocsp_status)));
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, server_config));

        EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));

        /* Verify that the client didn't receive an OCSP response. */
        EXPECT_NULL(s2n_connection_get_ocsp_response(client_conn, &length));
        EXPECT_EQUAL(length, 0);

        EXPECT_SUCCESS(s2n_shutdown_test_server_and_client(server_conn, client_conn));

        EXPECT_SUCCESS(s2n_connection_free(server_conn));
        EXPECT_SUCCESS(s2n_connection_free(client_conn));

        EXPECT_SUCCESS(s2n_config_free(server_config));

        for (int i = 0; i < 2; i++) {
           EXPECT_SUCCESS(close(server_to_client[i]));
           EXPECT_SUCCESS(close(client_to_server[i]));
        }
    }

    /* Server doesn't support the OCSP extension. */
    {
        struct s2n_connection *client_conn;
        struct s2n_connection *server_conn;
        struct s2n_config *server_config;
        struct s2n_config *client_config;
        int server_to_client[2];
        int client_to_server[2];
        uint32_t length;

        /* Create nonblocking pipes */
        EXPECT_SUCCESS(pipe(server_to_client));
        EXPECT_SUCCESS(pipe(client_to_server));
        for (int i = 0; i < 2; i++) {
           EXPECT_NOT_EQUAL(fcntl(server_to_client[i], F_SETFL, fcntl(server_to_client[i], F_GETFL) | O_NONBLOCK), -1);
           EXPECT_NOT_EQUAL(fcntl(client_to_server[i], F_SETFL, fcntl(client_to_server[i], F_GETFL) | O_NONBLOCK), -1);
        }

        EXPECT_NOT_NULL(client_config = s2n_config_new());
        EXPECT_NOT_NULL(client_conn = s2n_connection_new(S2N_CLIENT));
        client_conn->actual_protocol_version = S2N_TLS12;
        client_conn->server_protocol_version = S2N_TLS12;
        client_conn->client_protocol_version = S2N_TLS12;
        EXPECT_SUCCESS(s2n_connection_set_read_fd(client_conn, server_to_client[0]));
        EXPECT_SUCCESS(s2n_connection_set_write_fd(client_conn, client_to_server[1]));

        EXPECT_SUCCESS(s2n_config_set_status_request_type(client_config, S2N_STATUS_REQUEST_OCSP));
        EXPECT_SUCCESS(s2n_connection_set_config(client_conn, client_config));

        EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));
        server_conn->actual_protocol_version = S2N_TLS12;
        server_conn->server_protocol_version = S2N_TLS12;
        server_conn->client_protocol_version = S2N_TLS12;
        EXPECT_SUCCESS(s2n_connection_set_read_fd(server_conn, client_to_server[0]));
        EXPECT_SUCCESS(s2n_connection_set_write_fd(server_conn, server_to_client[1]));

        EXPECT_NOT_NULL(server_config = s2n_config_new());
        EXPECT_SUCCESS(s2n_read_test_pem(S2N_DEFAULT_TEST_CERT_CHAIN, cert_chain, S2N_MAX_TEST_PEM_SIZE));
        EXPECT_SUCCESS(s2n_read_test_pem(S2N_DEFAULT_TEST_PRIVATE_KEY, private_key, S2N_MAX_TEST_PEM_SIZE));
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key(server_config, cert_chain, private_key));
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, server_config));

        EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));

        /* Verify that the client didn't receive an OCSP response. */
        EXPECT_NULL(s2n_connection_get_ocsp_response(client_conn, &length));
        EXPECT_EQUAL(length, 0);

        EXPECT_SUCCESS(s2n_shutdown_test_server_and_client(server_conn, client_conn));

        EXPECT_SUCCESS(s2n_connection_free(server_conn));
        EXPECT_SUCCESS(s2n_connection_free(client_conn));

        EXPECT_SUCCESS(s2n_config_free(server_config));
        EXPECT_SUCCESS(s2n_config_free(client_config));

        for (int i = 0; i < 2; i++) {
           EXPECT_SUCCESS(close(server_to_client[i]));
           EXPECT_SUCCESS(close(client_to_server[i]));
        }
    }

    /* Server and client support the OCSP extension. */
    {
        struct s2n_connection *client_conn;
        struct s2n_connection *server_conn;
        struct s2n_config *server_config;
        struct s2n_config *client_config;
        const uint8_t *server_ocsp_reply;
        int server_to_client[2];
        int client_to_server[2];
        uint32_t length;

        /* Create nonblocking pipes */
        EXPECT_SUCCESS(pipe(server_to_client));
        EXPECT_SUCCESS(pipe(client_to_server));
        for (int i = 0; i < 2; i++) {
           EXPECT_NOT_EQUAL(fcntl(server_to_client[i], F_SETFL, fcntl(server_to_client[i], F_GETFL) | O_NONBLOCK), -1);
           EXPECT_NOT_EQUAL(fcntl(client_to_server[i], F_SETFL, fcntl(client_to_server[i], F_GETFL) | O_NONBLOCK), -1);
        }

        EXPECT_NOT_NULL(client_config = s2n_config_new());
        s2n_config_set_check_stapled_ocsp_response(client_config, 1);
        s2n_config_set_verification_ca_file(client_config, S2N_DEFAULT_TEST_CERT_CHAIN);
        s2n_config_set_nanoseconds_since_epoch_callback(client_config, fetch_valid_ocsp_timestamp, NULL);
        EXPECT_NOT_NULL(client_conn = s2n_connection_new(S2N_CLIENT));
        client_conn->actual_protocol_version = S2N_TLS12;
        client_conn->server_protocol_version = S2N_TLS12;
        client_conn->client_protocol_version = S2N_TLS12;
        EXPECT_SUCCESS(s2n_connection_set_read_fd(client_conn, server_to_client[0]));
        EXPECT_SUCCESS(s2n_connection_set_write_fd(client_conn, client_to_server[1]));

        EXPECT_SUCCESS(s2n_config_set_status_request_type(client_config, S2N_STATUS_REQUEST_OCSP));
        EXPECT_SUCCESS(s2n_connection_set_config(client_conn, client_config));

        EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));
        server_conn->actual_protocol_version = S2N_TLS12;
        server_conn->server_protocol_version = S2N_TLS12;
        server_conn->client_protocol_version = S2N_TLS12;
        EXPECT_SUCCESS(s2n_connection_set_read_fd(server_conn, client_to_server[0]));
        EXPECT_SUCCESS(s2n_connection_set_write_fd(server_conn, server_to_client[1]));

        EXPECT_NOT_NULL(server_config = s2n_config_new());
        EXPECT_SUCCESS(s2n_read_test_pem(S2N_DEFAULT_TEST_CERT_CHAIN, cert_chain, S2N_MAX_TEST_PEM_SIZE));
        EXPECT_SUCCESS(s2n_read_test_pem(S2N_DEFAULT_TEST_PRIVATE_KEY, private_key, S2N_MAX_TEST_PEM_SIZE));
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key(server_config, cert_chain, private_key));
        EXPECT_SUCCESS(s2n_config_set_extension_data(server_config, S2N_EXTENSION_OCSP_STAPLING, server_ocsp_status, sizeof(server_ocsp_status)));
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, server_config));

        EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));

        /* Verify that the client received an OCSP response. */
        EXPECT_NOT_NULL(server_ocsp_reply = s2n_connection_get_ocsp_response(client_conn, &length));
        EXPECT_EQUAL(length, sizeof(server_ocsp_status));

        for (int i = 0; i < sizeof(server_ocsp_status); i++) {
            EXPECT_EQUAL(server_ocsp_reply[i], server_ocsp_status[i]);
        }

        EXPECT_SUCCESS(s2n_shutdown_test_server_and_client(server_conn, client_conn));

        EXPECT_SUCCESS(s2n_connection_free(server_conn));
        EXPECT_SUCCESS(s2n_connection_free(client_conn));

        EXPECT_SUCCESS(s2n_config_free(server_config));
        EXPECT_SUCCESS(s2n_config_free(client_config));

        for (int i = 0; i < 2; i++) {
           EXPECT_SUCCESS(close(server_to_client[i]));
           EXPECT_SUCCESS(close(client_to_server[i]));
        }
    }

    /* Client does not request SCT, but server is configured to serve them. */
    {
        struct s2n_connection *client_conn;
        struct s2n_connection *server_conn;
        struct s2n_config *server_config;
        int server_to_client[2];
        int client_to_server[2];

        uint32_t length;

        /* Create nonblocking pipes */
        EXPECT_SUCCESS(pipe(server_to_client));
        EXPECT_SUCCESS(pipe(client_to_server));
        for (int i = 0; i < 2; i++) {
            EXPECT_NOT_EQUAL(fcntl(server_to_client[i], F_SETFL, fcntl(server_to_client[i], F_GETFL) | O_NONBLOCK), -1);
            EXPECT_NOT_EQUAL(fcntl(client_to_server[i], F_SETFL, fcntl(client_to_server[i], F_GETFL) | O_NONBLOCK), -1);
        }

        struct s2n_config *client_config;
        EXPECT_NOT_NULL(client_config = s2n_config_new());
        EXPECT_NOT_NULL(client_conn = s2n_connection_new(S2N_CLIENT));
        client_conn->actual_protocol_version = S2N_TLS12;
        client_conn->server_protocol_version = S2N_TLS12;
        client_conn->client_protocol_version = S2N_TLS12;
        EXPECT_SUCCESS(s2n_connection_set_read_fd(client_conn, server_to_client[0]));
        EXPECT_SUCCESS(s2n_connection_set_write_fd(client_conn, client_to_server[1]));

        EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));
        server_conn->actual_protocol_version = S2N_TLS12;
        server_conn->server_protocol_version = S2N_TLS12;
        server_conn->client_protocol_version = S2N_TLS12;
        EXPECT_SUCCESS(s2n_connection_set_read_fd(server_conn, client_to_server[0]));
        EXPECT_SUCCESS(s2n_connection_set_write_fd(server_conn, server_to_client[1]));

        EXPECT_NOT_NULL(server_config = s2n_config_new());
        EXPECT_SUCCESS(s2n_read_test_pem(S2N_DEFAULT_TEST_CERT_CHAIN, cert_chain, S2N_MAX_TEST_PEM_SIZE));
        EXPECT_SUCCESS(s2n_read_test_pem(S2N_DEFAULT_TEST_PRIVATE_KEY, private_key, S2N_MAX_TEST_PEM_SIZE));
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key(server_config, cert_chain, private_key));
        EXPECT_SUCCESS(s2n_config_set_extension_data(server_config, S2N_EXTENSION_CERTIFICATE_TRANSPARENCY, sct_list, sizeof(sct_list)));
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, server_config));

        EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));

        /* Verify that the client did *not* receive an SCT list */
        EXPECT_NULL(s2n_connection_get_sct_list(client_conn, &length));
        EXPECT_EQUAL(length, 0);

        EXPECT_SUCCESS(s2n_shutdown_test_server_and_client(server_conn, client_conn));

        EXPECT_SUCCESS(s2n_connection_free(server_conn));
        EXPECT_SUCCESS(s2n_connection_free(client_conn));

        EXPECT_SUCCESS(s2n_config_free(server_config));
        for (int i = 0; i < 2; i++) {
            EXPECT_SUCCESS(close(server_to_client[i]));
            EXPECT_SUCCESS(close(client_to_server[i]));
        }
    }

    /* Client requests SCT and server does have it. */
    {
        struct s2n_connection *client_conn;
        struct s2n_connection *server_conn;
        struct s2n_config *client_config;
        struct s2n_config *server_config;
        int server_to_client[2];
        int client_to_server[2];

        uint32_t length;

        /* Create nonblocking pipes */
        EXPECT_SUCCESS(pipe(server_to_client));
        EXPECT_SUCCESS(pipe(client_to_server));
        for (int i = 0; i < 2; i++) {
            EXPECT_NOT_EQUAL(fcntl(server_to_client[i], F_SETFL, fcntl(server_to_client[i], F_GETFL) | O_NONBLOCK), -1);
            EXPECT_NOT_EQUAL(fcntl(client_to_server[i], F_SETFL, fcntl(client_to_server[i], F_GETFL) | O_NONBLOCK), -1);
        }

        EXPECT_NOT_NULL(client_config = s2n_config_new());
        EXPECT_NOT_NULL(client_conn = s2n_connection_new(S2N_CLIENT));
        client_conn->actual_protocol_version = S2N_TLS12;
        client_conn->server_protocol_version = S2N_TLS12;
        client_conn->client_protocol_version = S2N_TLS12;
        EXPECT_SUCCESS(s2n_connection_set_read_fd(client_conn, server_to_client[0]));
        EXPECT_SUCCESS(s2n_connection_set_write_fd(client_conn, client_to_server[1]));

        /* Indicate that the client wants CT if available */
        EXPECT_SUCCESS(s2n_config_set_ct_support_level(client_config, S2N_CT_SUPPORT_REQUEST));
        EXPECT_SUCCESS(s2n_connection_set_config(client_conn, client_config));

        EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));
        server_conn->actual_protocol_version = S2N_TLS12;
        server_conn->server_protocol_version = S2N_TLS12;
        server_conn->client_protocol_version = S2N_TLS12;
        EXPECT_SUCCESS(s2n_connection_set_read_fd(server_conn, client_to_server[0]));
        EXPECT_SUCCESS(s2n_connection_set_write_fd(server_conn, server_to_client[1]));

        EXPECT_NOT_NULL(server_config = s2n_config_new());
        EXPECT_SUCCESS(s2n_read_test_pem(S2N_DEFAULT_TEST_CERT_CHAIN, cert_chain, S2N_MAX_TEST_PEM_SIZE));
        EXPECT_SUCCESS(s2n_read_test_pem(S2N_DEFAULT_TEST_PRIVATE_KEY, private_key, S2N_MAX_TEST_PEM_SIZE));
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key(server_config, cert_chain, private_key));
        EXPECT_SUCCESS(s2n_config_set_extension_data(server_config, S2N_EXTENSION_CERTIFICATE_TRANSPARENCY, sct_list, sizeof(sct_list)));
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, server_config));

        EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));

        /* Verify that the client did receive an SCT list */
        EXPECT_NOT_NULL(s2n_connection_get_sct_list(client_conn, &length));
        EXPECT_EQUAL(length, sizeof(sct_list));

        EXPECT_SUCCESS(s2n_shutdown_test_server_and_client(server_conn, client_conn));

        EXPECT_SUCCESS(s2n_connection_free(server_conn));
        EXPECT_SUCCESS(s2n_connection_free(client_conn));

        EXPECT_SUCCESS(s2n_config_free(server_config));
        for (int i = 0; i < 2; i++) {
            EXPECT_SUCCESS(close(server_to_client[i]));
            EXPECT_SUCCESS(close(client_to_server[i]));
        }
    }

    /* Client requests SCT and server does *not* have it. */
    {
        struct s2n_connection *client_conn;
        struct s2n_connection *server_conn;
        struct s2n_config *client_config;
        struct s2n_config *server_config;
        int server_to_client[2];
        int client_to_server[2];

        uint32_t length;

        /* Create nonblocking pipes */
        EXPECT_SUCCESS(pipe(server_to_client));
        EXPECT_SUCCESS(pipe(client_to_server));
        for (int i = 0; i < 2; i++) {
            EXPECT_NOT_EQUAL(fcntl(server_to_client[i], F_SETFL, fcntl(server_to_client[i], F_GETFL) | O_NONBLOCK), -1);
            EXPECT_NOT_EQUAL(fcntl(client_to_server[i], F_SETFL, fcntl(client_to_server[i], F_GETFL) | O_NONBLOCK), -1);
        }

        EXPECT_NOT_NULL(client_config = s2n_config_new());
        EXPECT_NOT_NULL(client_conn = s2n_connection_new(S2N_CLIENT));
        EXPECT_SUCCESS(s2n_connection_set_config(client_conn, client_config));
        client_conn->actual_protocol_version = S2N_TLS12;
        client_conn->server_protocol_version = S2N_TLS12;
        client_conn->client_protocol_version = S2N_TLS12;
        EXPECT_SUCCESS(s2n_connection_set_read_fd(client_conn, server_to_client[0]));
        EXPECT_SUCCESS(s2n_connection_set_write_fd(client_conn, client_to_server[1]));

        /* Indicate that the client wants CT if available */
        EXPECT_SUCCESS(s2n_config_set_ct_support_level(client_config, S2N_CT_SUPPORT_REQUEST));
        EXPECT_SUCCESS(s2n_connection_set_config(client_conn, client_config));

        EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));
        server_conn->actual_protocol_version = S2N_TLS12;
        server_conn->server_protocol_version = S2N_TLS12;
        server_conn->client_protocol_version = S2N_TLS12;
        EXPECT_SUCCESS(s2n_connection_set_read_fd(server_conn, client_to_server[0]));
        EXPECT_SUCCESS(s2n_connection_set_write_fd(server_conn, server_to_client[1]));

        EXPECT_NOT_NULL(server_config = s2n_config_new());
        EXPECT_SUCCESS(s2n_read_test_pem(S2N_DEFAULT_TEST_CERT_CHAIN, cert_chain, S2N_MAX_TEST_PEM_SIZE));
        EXPECT_SUCCESS(s2n_read_test_pem(S2N_DEFAULT_TEST_PRIVATE_KEY, private_key, S2N_MAX_TEST_PEM_SIZE));
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key(server_config, cert_chain, private_key));
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, server_config));

        EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));

        /* Verify that the client does not get a list */
        EXPECT_NULL(s2n_connection_get_sct_list(client_conn, &length));
        EXPECT_EQUAL(length, 0);

        EXPECT_SUCCESS(s2n_shutdown_test_server_and_client(server_conn, client_conn));

        EXPECT_SUCCESS(s2n_connection_free(server_conn));
        EXPECT_SUCCESS(s2n_connection_free(client_conn));

        EXPECT_SUCCESS(s2n_config_free(server_config));
        for (int i = 0; i < 2; i++) {
            EXPECT_SUCCESS(close(server_to_client[i]));
            EXPECT_SUCCESS(close(client_to_server[i]));
        }
    }

    /* Client requests 512, 1024, 2048, and 4096 maximum fragment lengths */
    for (uint8_t mfl_code = S2N_TLS_MAX_FRAG_LEN_512; mfl_code <= S2N_TLS_MAX_FRAG_LEN_4096; mfl_code++)
    {
        struct s2n_connection *client_conn;
        struct s2n_connection *server_conn;
        struct s2n_config *server_config;
        struct s2n_config *client_config;
        int server_to_client[2];
        int client_to_server[2];

        /* Create nonblocking pipes */
        EXPECT_SUCCESS(pipe(server_to_client));
        EXPECT_SUCCESS(pipe(client_to_server));
        for (int i = 0; i < 2; i++) {
           EXPECT_NOT_EQUAL(fcntl(server_to_client[i], F_SETFL, fcntl(server_to_client[i], F_GETFL) | O_NONBLOCK), -1);
           EXPECT_NOT_EQUAL(fcntl(client_to_server[i], F_SETFL, fcntl(client_to_server[i], F_GETFL) | O_NONBLOCK), -1);
        }

        EXPECT_NOT_NULL(client_conn = s2n_connection_new(S2N_CLIENT));
        client_conn->actual_protocol_version = S2N_TLS12;
        client_conn->server_protocol_version = S2N_TLS12;
        client_conn->client_protocol_version = S2N_TLS12;
        EXPECT_SUCCESS(s2n_connection_set_read_fd(client_conn, server_to_client[0]));
        EXPECT_SUCCESS(s2n_connection_set_write_fd(client_conn, client_to_server[1]));

        EXPECT_NOT_NULL(client_config = s2n_config_new());

        EXPECT_SUCCESS(s2n_config_send_max_fragment_length(client_config, mfl_code));
        EXPECT_SUCCESS(s2n_connection_set_config(client_conn, client_config));

        EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));
        server_conn->actual_protocol_version = S2N_TLS12;
        server_conn->server_protocol_version = S2N_TLS12;
        server_conn->client_protocol_version = S2N_TLS12;
        EXPECT_SUCCESS(s2n_connection_set_read_fd(server_conn, client_to_server[0]));
        EXPECT_SUCCESS(s2n_connection_set_write_fd(server_conn, server_to_client[1]));

        EXPECT_NOT_NULL(server_config = s2n_config_new());
        EXPECT_SUCCESS(s2n_config_accept_max_fragment_length(server_config));
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key(server_config, cert_chain, private_key));
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, server_config));

        /* Preference should be ignored as the TlS Maximum Fragment Length Extension is Set */
        EXPECT_SUCCESS(s2n_connection_prefer_throughput(server_conn));

        EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));

        EXPECT_EQUAL(server_conn->max_outgoing_fragment_length, mfl_code_to_length[mfl_code]);
        EXPECT_EQUAL(server_conn->mfl_code, mfl_code);

        EXPECT_SUCCESS(s2n_shutdown_test_server_and_client(server_conn, client_conn));

        EXPECT_SUCCESS(s2n_connection_free(server_conn));
        EXPECT_SUCCESS(s2n_connection_free(client_conn));

        EXPECT_SUCCESS(s2n_config_free(server_config));
        EXPECT_SUCCESS(s2n_config_free(client_config));

        for (int i = 0; i < 2; i++) {
           EXPECT_SUCCESS(close(server_to_client[i]));
           EXPECT_SUCCESS(close(client_to_server[i]));
        }
    }

    /* Client requests invalid maximum fragment length */
    {
        struct s2n_connection *client_conn;
        struct s2n_connection *server_conn;
        struct s2n_config *server_config;
        struct s2n_config *client_config;
        int server_to_client[2];
        int client_to_server[2];

        /* Create nonblocking pipes */
        EXPECT_SUCCESS(pipe(server_to_client));
        EXPECT_SUCCESS(pipe(client_to_server));
        for (int i = 0; i < 2; i++) {
           EXPECT_NOT_EQUAL(fcntl(server_to_client[i], F_SETFL, fcntl(server_to_client[i], F_GETFL) | O_NONBLOCK), -1);
           EXPECT_NOT_EQUAL(fcntl(client_to_server[i], F_SETFL, fcntl(client_to_server[i], F_GETFL) | O_NONBLOCK), -1);
        }

        EXPECT_NOT_NULL(client_conn = s2n_connection_new(S2N_CLIENT));
        client_conn->actual_protocol_version = S2N_TLS12;
        client_conn->server_protocol_version = S2N_TLS12;
        client_conn->client_protocol_version = S2N_TLS12;
        EXPECT_SUCCESS(s2n_connection_set_read_fd(client_conn, server_to_client[0]));
        EXPECT_SUCCESS(s2n_connection_set_write_fd(client_conn, client_to_server[1]));

        EXPECT_NOT_NULL(client_config = s2n_config_new());
        EXPECT_FAILURE(s2n_config_send_max_fragment_length(client_config, 5));
        EXPECT_SUCCESS(s2n_connection_set_config(client_conn, client_config));

        EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));
        server_conn->actual_protocol_version = S2N_TLS12;
        server_conn->server_protocol_version = S2N_TLS12;
        server_conn->client_protocol_version = S2N_TLS12;
        EXPECT_SUCCESS(s2n_connection_set_read_fd(server_conn, client_to_server[0]));
        EXPECT_SUCCESS(s2n_connection_set_write_fd(server_conn, server_to_client[1]));

        EXPECT_NOT_NULL(server_config = s2n_config_new());
        EXPECT_SUCCESS(s2n_config_accept_max_fragment_length(server_config));
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key(server_config, cert_chain, private_key));
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, server_config));

        EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));

        /* check that max_fragment_length did not get set due to invalid mfl_code */
        EXPECT_EQUAL(server_conn->max_outgoing_fragment_length, S2N_DEFAULT_FRAGMENT_LENGTH);
        EXPECT_EQUAL(server_conn->mfl_code, S2N_TLS_MAX_FRAG_LEN_EXT_NONE);

        EXPECT_SUCCESS(s2n_shutdown_test_server_and_client(server_conn, client_conn));

        EXPECT_SUCCESS(s2n_connection_free(server_conn));
        EXPECT_SUCCESS(s2n_connection_free(client_conn));

        EXPECT_SUCCESS(s2n_config_free(server_config));
        EXPECT_SUCCESS(s2n_config_free(client_config));

        for (int i = 0; i < 2; i++) {
           EXPECT_SUCCESS(close(server_to_client[i]));
           EXPECT_SUCCESS(close(client_to_server[i]));
        }
    }

    /* Server ignores client's request of S2N_TLS_MAX_FRAG_LEN_2048 maximum fragment length when accept_mfl is not set*/
    {
        struct s2n_connection *client_conn;
        struct s2n_connection *server_conn;
        struct s2n_config *server_config;
        struct s2n_config *client_config;
        int server_to_client[2];
        int client_to_server[2];

        /* Create nonblocking pipes */
        EXPECT_SUCCESS(pipe(server_to_client));
        EXPECT_SUCCESS(pipe(client_to_server));
        for (int i = 0; i < 2; i++) {
           EXPECT_NOT_EQUAL(fcntl(server_to_client[i], F_SETFL, fcntl(server_to_client[i], F_GETFL) | O_NONBLOCK), -1);
           EXPECT_NOT_EQUAL(fcntl(client_to_server[i], F_SETFL, fcntl(client_to_server[i], F_GETFL) | O_NONBLOCK), -1);
        }

        EXPECT_NOT_NULL(client_conn = s2n_connection_new(S2N_CLIENT));
        client_conn->actual_protocol_version = S2N_TLS12;
        client_conn->server_protocol_version = S2N_TLS12;
        client_conn->client_protocol_version = S2N_TLS12;
        EXPECT_SUCCESS(s2n_connection_set_read_fd(client_conn, server_to_client[0]));
        EXPECT_SUCCESS(s2n_connection_set_write_fd(client_conn, client_to_server[1]));

        EXPECT_NOT_NULL(client_config = s2n_config_new());
        EXPECT_SUCCESS(s2n_config_send_max_fragment_length(client_config, S2N_TLS_MAX_FRAG_LEN_2048));
        EXPECT_SUCCESS(s2n_connection_set_config(client_conn, client_config));

        EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));
        server_conn->actual_protocol_version = S2N_TLS12;
        server_conn->server_protocol_version = S2N_TLS12;
        server_conn->client_protocol_version = S2N_TLS12;
        EXPECT_SUCCESS(s2n_connection_set_read_fd(server_conn, client_to_server[0]));
        EXPECT_SUCCESS(s2n_connection_set_write_fd(server_conn, server_to_client[1]));

        EXPECT_NOT_NULL(server_config = s2n_config_new());
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key(server_config, cert_chain, private_key));
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, server_config));

        EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));

        /* check that max_fragment_length did not get set since accept_mfl is not set */
        EXPECT_EQUAL(server_conn->max_outgoing_fragment_length, S2N_DEFAULT_FRAGMENT_LENGTH);
        EXPECT_EQUAL(server_conn->mfl_code, S2N_TLS_MAX_FRAG_LEN_EXT_NONE);

        EXPECT_SUCCESS(s2n_shutdown_test_server_and_client(server_conn, client_conn));

        EXPECT_SUCCESS(s2n_connection_free(server_conn));
        EXPECT_SUCCESS(s2n_connection_free(client_conn));

        EXPECT_SUCCESS(s2n_config_free(server_config));
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

