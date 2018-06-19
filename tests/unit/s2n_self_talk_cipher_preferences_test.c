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

#include <s2n.h>
#include <errno.h>

#include "tls/s2n_connection.h"
#include "tls/s2n_handshake.h"

void mock_client(int writefd, int readfd)
{
    struct s2n_connection *conn;
    struct s2n_config *config;
    struct s2n_cipher_preferences *ciphers;
    s2n_blocked_status blocked;
    int ciphers_count = 1;
    int result = 0;

    /* Give the server a chance to listen */
    sleep(1);

    /* Both server and client only support one common cipher suite, handshake should complete */
    conn = s2n_connection_new(S2N_CLIENT);
    config = s2n_config_new();

    ciphers = s2n_cipher_preferences_new();
    s2n_cipher_suite_type cipher_suites[] = { S2N_ECDHE_RSA_WITH_AES_128_GCM_SHA256 };
    s2n_cipher_preferences_set_cipher_suites(ciphers, cipher_suites, ciphers_count);
    s2n_cipher_preferences_set_min_tls_version(ciphers, S2N_TLS_VERSION_TLS12);
    s2n_config_set_custom_cipher_preferences(config, ciphers);

    s2n_config_disable_x509_verification(config);
    s2n_connection_set_config(conn, config);

    s2n_connection_set_read_fd(conn, readfd);
    s2n_connection_set_write_fd(conn, writefd);

    if (s2n_negotiate(conn, &blocked) != 0) {
        result = 1;
    }

    /* Shutdown handshake */
    int shutdown_rc = -1;
    do {
        shutdown_rc = s2n_shutdown(conn, &blocked);
    } while(shutdown_rc != 0);

    s2n_connection_free(conn);

    /* Give the server a chance to avoid sigpipe */
    sleep(1);

    /* Both server and client only support one but different cipher suite, handshake should fail */
    conn = s2n_connection_new(S2N_CLIENT);

    cipher_suites[0] = S2N_RSA_WITH_RC4_128_SHA;
    s2n_cipher_preferences_set_cipher_suites(ciphers, cipher_suites, ciphers_count);

    s2n_connection_set_config(conn, config);

    s2n_connection_set_read_fd(conn, readfd);
    s2n_connection_set_write_fd(conn, writefd);

    if (s2n_negotiate(conn, &blocked) == 0) {
        result = 2;
    }

    s2n_connection_free(conn);
    s2n_cipher_preferences_free(ciphers);
    s2n_config_free(config);

    /* Give the server a chance to avoid sigpipe */
    sleep(1);

    _exit(result);
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
    struct s2n_cipher_preferences *ciphers;
    int ciphers_count = 1;
    int shutdown_rc = -1;

    BEGIN_TEST();
    EXPECT_NOT_NULL(cert_chain_pem = malloc(S2N_MAX_TEST_PEM_SIZE));
    EXPECT_NOT_NULL(private_key_pem = malloc(S2N_MAX_TEST_PEM_SIZE));

    EXPECT_SUCCESS(setenv("S2N_ENABLE_CLIENT_MODE", "1", 0));

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

    EXPECT_SUCCESS(s2n_read_test_pem(S2N_DEFAULT_TEST_CERT_CHAIN, cert_chain_pem, S2N_MAX_TEST_PEM_SIZE));
    EXPECT_SUCCESS(s2n_read_test_pem(S2N_DEFAULT_TEST_PRIVATE_KEY, private_key_pem, S2N_MAX_TEST_PEM_SIZE));
    
    EXPECT_NOT_NULL(config = s2n_config_new());
    EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key(config, cert_chain_pem, private_key_pem));
    
    EXPECT_NOT_NULL(ciphers = s2n_cipher_preferences_new());
    s2n_cipher_suite_type cipher_suites[] = { S2N_ECDHE_RSA_WITH_AES_128_GCM_SHA256 };
    EXPECT_SUCCESS(s2n_cipher_preferences_set_cipher_suites(ciphers, cipher_suites, ciphers_count));
    EXPECT_SUCCESS(s2n_cipher_preferences_set_min_tls_version(ciphers, S2N_TLS_VERSION_TLS12))
    EXPECT_SUCCESS(s2n_config_set_custom_cipher_preferences(config, ciphers));

    /* Both server and client only support one common cipher suite, handshake should complete */
    {
        EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));
        EXPECT_SUCCESS(s2n_connection_set_config(conn, config));

        /* Set up the connection to read from the fd */
        EXPECT_SUCCESS(s2n_connection_set_read_fd(conn, client_to_server[0]));
        EXPECT_SUCCESS(s2n_connection_set_write_fd(conn, server_to_client[1]));

        /* Negotiate the handshake. */
        EXPECT_SUCCESS(s2n_negotiate(conn, &blocked));

        /* Shutdown handshake */
        do {
            shutdown_rc = s2n_shutdown(conn, &blocked);
            EXPECT_TRUE(shutdown_rc == 0 || (errno == EAGAIN && blocked));
        } while(shutdown_rc != 0);

        EXPECT_SUCCESS(s2n_connection_free(conn));
    }

    /* Both server and client only support one but different cipher suite, handshake should fail */
    {
        EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));

        /* Set up the connection to read from the fd */
        EXPECT_SUCCESS(s2n_connection_set_read_fd(conn, client_to_server[0]));
        EXPECT_SUCCESS(s2n_connection_set_write_fd(conn, server_to_client[1]));

        /* Negotiate the handshake. */
        EXPECT_FAILURE(s2n_negotiate(conn, &blocked));

        EXPECT_SUCCESS(s2n_connection_free(conn));
    }

    /* Close the pipes */
    EXPECT_SUCCESS(close(client_to_server[0]));
    EXPECT_SUCCESS(close(server_to_client[1]));

    /* Clean up */
    EXPECT_SUCCESS(s2n_config_free(config));
    EXPECT_SUCCESS(s2n_cipher_preferences_free(ciphers));

    EXPECT_EQUAL(waitpid(-1, &status, 0), pid);
    EXPECT_EQUAL(status, 0);

    free(cert_chain_pem);
    free(private_key_pem);

    END_TEST();
    return 0;
}
