/*
 * Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

#include <s2n.h>

#include "tls/s2n_connection.h"
#include "tls/s2n_handshake.h"

int mock_client(int writefd, int readfd)
{
    struct s2n_connection *client_conn;
    struct s2n_config *client_config;
    s2n_blocked_status blocked;
    int result = 0;

    client_config = s2n_config_new();
    s2n_config_disable_x509_verification(client_config);

    client_conn = s2n_connection_new(S2N_CLIENT);
    s2n_connection_set_config(client_conn, client_config);
    s2n_connection_set_blinding(client_conn, S2N_SELF_SERVICE_BLINDING);

    /* Force TLSv1 on a client so that server fail handshake */
    client_conn->client_protocol_version = S2N_TLS10;

    s2n_connection_set_read_fd(client_conn, readfd);
    s2n_connection_set_write_fd(client_conn, writefd);

    result = s2n_negotiate(client_conn, &blocked);

    s2n_connection_free(client_conn);
    s2n_config_free(client_config);

    s2n_cleanup();

    /* Expect failure of handshake */
    _exit(result == 0 ? 1 : 0);
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
    struct s2n_cert_chain_and_key *chain_and_key;

    BEGIN_TEST();

    /* Ignore SIGPIPE */
    signal(SIGPIPE, SIG_IGN);

    EXPECT_NOT_NULL(cert_chain_pem = malloc(S2N_MAX_TEST_PEM_SIZE));
    EXPECT_NOT_NULL(private_key_pem = malloc(S2N_MAX_TEST_PEM_SIZE));

    EXPECT_SUCCESS(s2n_read_test_pem(S2N_DEFAULT_TEST_CERT_CHAIN, cert_chain_pem, S2N_MAX_TEST_PEM_SIZE));
    EXPECT_SUCCESS(s2n_read_test_pem(S2N_DEFAULT_TEST_PRIVATE_KEY, private_key_pem, S2N_MAX_TEST_PEM_SIZE));
    EXPECT_NOT_NULL(chain_and_key = s2n_cert_chain_and_key_new());
    EXPECT_SUCCESS(s2n_cert_chain_and_key_load_pem(chain_and_key, cert_chain_pem, private_key_pem));

    EXPECT_NOT_NULL(config = s2n_config_new());
    EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(config, chain_and_key));
    /* Pick cipher preference with TLSv1.2 as a minimum version */
    EXPECT_SUCCESS(s2n_config_set_cipher_preferences(config, "CloudFront-TLS-1-2-2019"));

    /* Create a pipe */
    EXPECT_SUCCESS(pipe(server_to_client));
    EXPECT_SUCCESS(pipe(client_to_server));

    /* Create a child process */
    pid = fork();
    if (pid == 0) {
        /* This is the child process, close the read end of the pipe */
        EXPECT_SUCCESS(close(client_to_server[0]));
        EXPECT_SUCCESS(close(server_to_client[1]));

        /* Send the client hello with TLSv1 and validate that we failed handshake */
        mock_client(client_to_server[1], server_to_client[0]);
    }

    /* This is the parent */
    EXPECT_SUCCESS(close(client_to_server[1]));
    EXPECT_SUCCESS(close(server_to_client[0]));

    EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));
    EXPECT_SUCCESS(s2n_connection_set_config(conn, config));
    EXPECT_SUCCESS(s2n_connection_set_blinding(conn, S2N_SELF_SERVICE_BLINDING));

    /* Set up the connection to read from the fd */
    EXPECT_SUCCESS(s2n_connection_set_read_fd(conn, client_to_server[0]));
    EXPECT_SUCCESS(s2n_connection_set_write_fd(conn, server_to_client[1]));

    /* Negotiate the handshake. */
    EXPECT_FAILURE_WITH_ERRNO(s2n_negotiate(conn, &blocked), S2N_ERR_PROTOCOL_VERSION_UNSUPPORTED);

    /* Check that blinding was not invoked */
    EXPECT_EQUAL(s2n_connection_get_delay(conn), 0);

    /* Free connection */
    EXPECT_SUCCESS(s2n_connection_free(conn));

    /* Close the pipes */
    EXPECT_SUCCESS(close(client_to_server[0]));
    EXPECT_SUCCESS(close(server_to_client[1]));

    /* Clean up */
    EXPECT_EQUAL(waitpid(-1, &status, 0), pid);
    EXPECT_EQUAL(status, 0);

    EXPECT_SUCCESS(s2n_config_free(config));
    EXPECT_SUCCESS(s2n_cert_chain_and_key_free(chain_and_key));
    free(cert_chain_pem);
    free(private_key_pem);
    END_TEST();

    return 0;
}
