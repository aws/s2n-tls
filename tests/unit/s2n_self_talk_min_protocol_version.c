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

#include <sys/wait.h>
#include <unistd.h>
#include <stdint.h>
#include <fcntl.h>

#include <s2n.h>

#include "tls/s2n_connection.h"
#include "tls/s2n_handshake.h"

int mock_client(struct s2n_test_piped_io *piped_io)
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

    /* Force TLSv1 on a client so that server will fail handshake */
    client_conn->client_protocol_version = S2N_TLS10;

    s2n_connection_set_piped_io(client_conn, piped_io);

    result = s2n_negotiate(client_conn, &blocked);

    s2n_piped_io_close_one_end(piped_io, S2N_CLIENT);
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
    char cert_chain_pem[S2N_MAX_TEST_PEM_SIZE];
    char private_key_pem[S2N_MAX_TEST_PEM_SIZE];
    struct s2n_cert_chain_and_key *chain_and_key;

    BEGIN_TEST();

    EXPECT_SUCCESS(s2n_read_test_pem(S2N_DEFAULT_TEST_CERT_CHAIN, cert_chain_pem, S2N_MAX_TEST_PEM_SIZE));
    EXPECT_SUCCESS(s2n_read_test_pem(S2N_DEFAULT_TEST_PRIVATE_KEY, private_key_pem, S2N_MAX_TEST_PEM_SIZE));
    EXPECT_NOT_NULL(chain_and_key = s2n_cert_chain_and_key_new());
    EXPECT_SUCCESS(s2n_cert_chain_and_key_load_pem(chain_and_key, cert_chain_pem, private_key_pem));

    EXPECT_NOT_NULL(config = s2n_config_new());
    EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(config, chain_and_key));
    /* Pick cipher preference with TLSv1.2 as a minimum version */
    EXPECT_SUCCESS(s2n_config_set_cipher_preferences(config, "CloudFront-TLS-1-2-2019"));

    /* Create a pipe */
    struct s2n_test_piped_io piped_io;
    EXPECT_SUCCESS(s2n_piped_io_init(&piped_io));

    /* Create a child process */
    pid = fork();
    if (pid == 0) {
        /* This is the client process, close the server end of the pipe */
        EXPECT_SUCCESS(s2n_piped_io_close_one_end(&piped_io, S2N_SERVER));

        /* Send the client hello with TLSv1 and validate that we failed handshake */
        mock_client(&piped_io);
    }

    /* This is the server process, close the client end of the pipe */
    EXPECT_SUCCESS(s2n_piped_io_close_one_end(&piped_io, S2N_CLIENT));

    EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));
    EXPECT_SUCCESS(s2n_connection_set_config(conn, config));
    EXPECT_SUCCESS(s2n_connection_set_blinding(conn, S2N_SELF_SERVICE_BLINDING));

    /* Set up the connection to read from the fd */
    EXPECT_SUCCESS(s2n_connection_set_piped_io(conn, &piped_io));

    /* Negotiate the handshake. */
    EXPECT_FAILURE_WITH_ERRNO(s2n_negotiate(conn, &blocked), S2N_ERR_PROTOCOL_VERSION_UNSUPPORTED);

    /* Check that blinding was not invoked */
    EXPECT_EQUAL(s2n_connection_get_delay(conn), 0);

    /* Free connection */
    EXPECT_SUCCESS(s2n_connection_free(conn));

    /* Close the pipes */
    EXPECT_SUCCESS(s2n_piped_io_close_one_end(&piped_io, S2N_SERVER));

    /* Clean up */
    EXPECT_EQUAL(waitpid(-1, &status, 0), pid);
    EXPECT_EQUAL(status, 0);

    EXPECT_SUCCESS(s2n_config_free(config));
    EXPECT_SUCCESS(s2n_cert_chain_and_key_free(chain_and_key));
    END_TEST();

    return 0;
}
