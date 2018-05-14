/*
 * Copyright 2014 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

#include <s2n.h>

#include "tls/s2n_connection.h"
#include "tls/s2n_handshake.h"

#define SUPPORTED_CERTIFICATE_FORMATS (2)

static const char *certificate_paths[SUPPORTED_CERTIFICATE_FORMATS] = { S2N_RSA_2048_PKCS1_CERT_CHAIN, S2N_RSA_2048_PKCS8_CERT_CHAIN };
static const char *private_key_paths[SUPPORTED_CERTIFICATE_FORMATS] = { S2N_RSA_2048_PKCS1_KEY, S2N_RSA_2048_PKCS8_KEY };

void mock_client(int writefd, int readfd)
{
    char buffer[0xffff];
    struct s2n_connection *conn;
    struct s2n_config *config;
    s2n_blocked_status blocked;

    /* Give the server a chance to listen */
    sleep(1);

    conn = s2n_connection_new(S2N_CLIENT);
    config = s2n_config_new();
    s2n_config_disable_x509_verification(config);
    s2n_connection_set_config(conn, config);
    conn->server_protocol_version = S2N_TLS12;
    conn->client_protocol_version = S2N_TLS12;
    conn->actual_protocol_version = S2N_TLS12;

    s2n_connection_set_read_fd(conn, readfd);
    s2n_connection_set_write_fd(conn, writefd);

    s2n_negotiate(conn, &blocked);

    for (int i = 1; i < 0xffff; i += 100) {
        for (int j = 0; j < i; j++) {
            buffer[j] = 33;
        }

        s2n_send(conn, buffer, i, &blocked);
    }

    int shutdown_rc = -1;
    while(shutdown_rc != 0) {
        shutdown_rc = s2n_shutdown(conn, &blocked);
    }

    s2n_connection_free(conn);
    s2n_config_free(config);

    /* Give the server a chance to a void a sigpipe */
    sleep(1);

    _exit(0);
}

int main(int argc, char **argv)
{
    struct s2n_connection *conn;
    struct s2n_config *config;
    s2n_blocked_status blocked;
    int status;
    pid_t pid;
    int server_to_client[2];
    int client_to_server[2];
    char *cert_chain_pem;
    char *private_key_pem;
    char *dhparams_pem;

    BEGIN_TEST();
    EXPECT_NOT_NULL(cert_chain_pem = malloc(S2N_MAX_TEST_PEM_SIZE));
    EXPECT_NOT_NULL(private_key_pem = malloc(S2N_MAX_TEST_PEM_SIZE));
    EXPECT_NOT_NULL(dhparams_pem = malloc(S2N_MAX_TEST_PEM_SIZE));

    EXPECT_SUCCESS(setenv("S2N_ENABLE_CLIENT_MODE", "1", 0));

    for (int cert = 0; cert < SUPPORTED_CERTIFICATE_FORMATS; cert++) {
        for (int is_dh_key_exchange = 0; is_dh_key_exchange <= 1; is_dh_key_exchange++) {
            /* Create a pipe */
            EXPECT_SUCCESS(pipe(server_to_client));
            EXPECT_SUCCESS(pipe(client_to_server));

            /* Create a child process */
            pid = fork();
            if (pid == 0) {
                /* This is the child process, close the read end of the pipe */
                EXPECT_SUCCESS(close(client_to_server[0]));
                EXPECT_SUCCESS(close(server_to_client[1]));

                /* Write the fragmented hello message */
                mock_client(client_to_server[1], server_to_client[0]);
            }

            /* This is the parent */
            EXPECT_SUCCESS(close(client_to_server[1]));
            EXPECT_SUCCESS(close(server_to_client[0]));

            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));
            conn->server_protocol_version = S2N_TLS12;
            conn->client_protocol_version = S2N_TLS12;
            conn->actual_protocol_version = S2N_TLS12;

            EXPECT_NOT_NULL(config = s2n_config_new());

            EXPECT_SUCCESS(s2n_read_test_pem(certificate_paths[cert], cert_chain_pem, S2N_MAX_TEST_PEM_SIZE));
            EXPECT_SUCCESS(s2n_read_test_pem(private_key_paths[cert], private_key_pem, S2N_MAX_TEST_PEM_SIZE));
            EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key(config, cert_chain_pem, private_key_pem));
            if (is_dh_key_exchange) {
                EXPECT_SUCCESS(s2n_read_test_pem(S2N_DEFAULT_TEST_DHPARAMS, dhparams_pem, S2N_MAX_TEST_PEM_SIZE));
                EXPECT_SUCCESS(s2n_config_add_dhparams(config, dhparams_pem));
            }

            EXPECT_SUCCESS(s2n_connection_set_config(conn, config));

            /* Set up the connection to read from the fd */
            EXPECT_SUCCESS(s2n_connection_set_read_fd(conn, client_to_server[0]));
            EXPECT_SUCCESS(s2n_connection_set_write_fd(conn, server_to_client[1]));

            /* Negotiate the handshake. */
            EXPECT_SUCCESS(s2n_negotiate(conn, &blocked));

            char buffer[0xffff];
            for (int i = 1; i < 0xffff; i += 100) {
                char * ptr = buffer;
                int size = i;

                do {
                    int bytes_read = 0;
                    EXPECT_SUCCESS(bytes_read = s2n_recv(conn, ptr, size, &blocked));

                    size -= bytes_read;
                    ptr += bytes_read;
                } while(size);

                for (int j = 0; j < i; j++) {
                    EXPECT_EQUAL(buffer[j], 33);
                }
            }

            int shutdown_rc = -1;
            do {
                shutdown_rc = s2n_shutdown(conn, &blocked);
                EXPECT_TRUE(shutdown_rc == 0 || (errno == EAGAIN && blocked));
            } while(shutdown_rc != 0);

            EXPECT_SUCCESS(s2n_connection_free(conn));

            EXPECT_SUCCESS(s2n_config_free(config));

            /* Clean up */
            EXPECT_EQUAL(waitpid(-1, &status, 0), pid);
            EXPECT_EQUAL(status, 0);
        }
    }

    free(cert_chain_pem);
    free(private_key_pem);
    free(dhparams_pem);

    END_TEST();
    return 0;
}
