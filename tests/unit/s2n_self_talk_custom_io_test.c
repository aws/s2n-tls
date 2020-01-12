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

#include <sys/poll.h>
#include <sys/wait.h>
#include <unistd.h>
#include <signal.h>
#include <stdint.h>
#include <fcntl.h>

#include <s2n.h>

#include "utils/s2n_random.h"

#include "tls/s2n_connection.h"
#include "tls/s2n_handshake.h"

#define MAX_BUF_SIZE 10000

int mock_client(int writefd, int readfd)
{
    struct s2n_connection *conn;
    struct s2n_config *client_config;
    s2n_blocked_status blocked;
    int result = 0;

    conn = s2n_connection_new(S2N_CLIENT);
    client_config = s2n_config_new();
    s2n_config_disable_x509_verification(client_config);
    s2n_connection_set_config(conn, client_config);

    /* Unlike the server, the client just passes ownership of I/O to s2n */
    s2n_connection_set_read_fd(conn, readfd);
    s2n_connection_set_write_fd(conn, writefd);

    result = s2n_negotiate(conn, &blocked);
    if (result < 0) {
        _exit(1);
    }

    s2n_shutdown(conn, &blocked);
    s2n_connection_free(conn);
    s2n_config_free(client_config);
    s2n_cleanup();

    _exit(0);
}

/**
 * This test creates a server, client, and a pair of pipes. The client uses the
 * pipes directly for I/O in s2n. The server copies data from the pipes into
 * stuffers and manages s2n I/O with a set of I/O callbacks that read and write
 * from the stuffers. 
 */
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
    struct s2n_cert_chain_and_key *chain_and_key;
    struct s2n_stuffer in, out;

    BEGIN_TEST();

    EXPECT_NOT_NULL(config = s2n_config_new());
    EXPECT_NOT_NULL(cert_chain_pem = malloc(S2N_MAX_TEST_PEM_SIZE));
    EXPECT_NOT_NULL(private_key_pem = malloc(S2N_MAX_TEST_PEM_SIZE));
    EXPECT_NOT_NULL(dhparams_pem = malloc(S2N_MAX_TEST_PEM_SIZE));
    EXPECT_SUCCESS(s2n_read_test_pem(S2N_DEFAULT_TEST_CERT_CHAIN, cert_chain_pem, S2N_MAX_TEST_PEM_SIZE));
    EXPECT_SUCCESS(s2n_read_test_pem(S2N_DEFAULT_TEST_PRIVATE_KEY, private_key_pem, S2N_MAX_TEST_PEM_SIZE));
    EXPECT_SUCCESS(s2n_read_test_pem(S2N_DEFAULT_TEST_DHPARAMS, dhparams_pem, S2N_MAX_TEST_PEM_SIZE));
    EXPECT_NOT_NULL(chain_and_key = s2n_cert_chain_and_key_new());
    EXPECT_SUCCESS(s2n_cert_chain_and_key_load_pem(chain_and_key, cert_chain_pem, private_key_pem));
    EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(config, chain_and_key));
    EXPECT_SUCCESS(s2n_config_add_dhparams(config, dhparams_pem));

    /* For convenience, this test will intentionally try to write to closed pipes during shutdown. Ignore the signal to
     * avoid exiting the process on SIGPIPE.
     */
    signal(SIGPIPE, SIG_IGN);

    /* Create a pipe */
    EXPECT_SUCCESS(pipe(server_to_client));
    EXPECT_SUCCESS(pipe(client_to_server));

    /* Create a child process */
    pid = fork();
    if (pid == 0) {
        /* This is the child process, close the read end of the pipe */
        EXPECT_SUCCESS(close(client_to_server[0]));
        EXPECT_SUCCESS(close(server_to_client[1]));

        /* Free the config */
        EXPECT_SUCCESS(s2n_config_free(config));
        free(cert_chain_pem);
        free(private_key_pem);
        free(dhparams_pem);

        /* Run the client */
        mock_client(client_to_server[1], server_to_client[0]);
    }

    /* This is the parent, close the write end of the pipe */
    EXPECT_SUCCESS(close(client_to_server[1]));
    EXPECT_SUCCESS(close(server_to_client[0]));

    EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));
    EXPECT_SUCCESS(s2n_connection_set_config(conn, config));

    EXPECT_FAILURE(s2n_connection_use_corked_io(conn));

    /* Set up our I/O callbacks. Use stuffers for the "I/O context" */
    EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&in, 0));
    EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&out, 0));
    EXPECT_SUCCESS(s2n_connection_set_io_stuffers(&in, &out, conn));
    
    /* Make our pipes non-blocking */
    EXPECT_NOT_EQUAL(fcntl(client_to_server[0], F_SETFL, fcntl(client_to_server[0], F_GETFL) | O_NONBLOCK), -1);
    EXPECT_NOT_EQUAL(fcntl(server_to_client[1], F_SETFL, fcntl(server_to_client[1], F_GETFL) | O_NONBLOCK), -1);

    /* Negotiate the handshake. */
    do {
        int ret;

        ret = s2n_negotiate(conn, &blocked);
        EXPECT_TRUE(ret == 0 || (blocked && (errno == EAGAIN || errno == EWOULDBLOCK)));
        
        /* check to see if we need to copy more over from the pipes to the buffers
         * to continue the handshake
         */
        s2n_stuffer_recv_from_fd(&in, client_to_server[0], MAX_BUF_SIZE);
        s2n_stuffer_send_to_fd(&out, server_to_client[1], s2n_stuffer_data_available(&out));
    } while (blocked);
   
    /* Shutdown after negotiating */
    uint8_t server_shutdown=0;
    do {
        int ret;
        
        ret = s2n_shutdown(conn, &blocked);
        EXPECT_TRUE(ret == 0 || (blocked && (errno == EAGAIN || errno == EWOULDBLOCK)));
        if (ret == 0) {
            server_shutdown = 1;
        }
        
        s2n_stuffer_recv_from_fd(&in, client_to_server[0], MAX_BUF_SIZE);
        s2n_stuffer_send_to_fd(&out, server_to_client[1], s2n_stuffer_data_available(&out));
    } while (!server_shutdown);
    
    EXPECT_SUCCESS(s2n_connection_free(conn));

    /* Clean up */
    EXPECT_SUCCESS(s2n_stuffer_free(&in));
    EXPECT_SUCCESS(s2n_stuffer_free(&out));
    EXPECT_EQUAL(waitpid(-1, &status, 0), pid);
    EXPECT_EQUAL(status, 0);
    EXPECT_SUCCESS(s2n_config_free(config));
    EXPECT_SUCCESS(s2n_cert_chain_and_key_free(chain_and_key));
    free(cert_chain_pem);
    free(private_key_pem);
    free(dhparams_pem);

    s2n_cleanup();

    END_TEST();

    return 0;
}

