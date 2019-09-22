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

static const uint8_t buf_to_send[1023] = { 27 };

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

    if (s2n_send(conn, buf_to_send, sizeof(buf_to_send), &blocked) != sizeof(buf_to_send)) {
        _exit(2);
    }

    s2n_shutdown(conn, &blocked);
    s2n_connection_free(conn);
    s2n_config_free(client_config);
    s2n_cleanup();

    _exit(0);
}

/**
 * This test ensures that we don't allow releasing connection buffers if they contain part
 * of the unprocessed record, avoiding conneciton corruption.
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
    struct s2n_cert_chain_and_key *chain_and_key;
    struct s2n_stuffer in, out;
    uint8_t buf[sizeof(buf_to_send)];
    ssize_t n, ret;

    BEGIN_TEST();

    EXPECT_NOT_NULL(config = s2n_config_new());
    EXPECT_NOT_NULL(cert_chain_pem = malloc(S2N_MAX_TEST_PEM_SIZE));
    EXPECT_NOT_NULL(private_key_pem = malloc(S2N_MAX_TEST_PEM_SIZE));
    EXPECT_SUCCESS(s2n_read_test_pem(S2N_DEFAULT_TEST_CERT_CHAIN, cert_chain_pem, S2N_MAX_TEST_PEM_SIZE));
    EXPECT_SUCCESS(s2n_read_test_pem(S2N_DEFAULT_TEST_PRIVATE_KEY, private_key_pem, S2N_MAX_TEST_PEM_SIZE));
    EXPECT_NOT_NULL(chain_and_key = s2n_cert_chain_and_key_new());
    EXPECT_SUCCESS(s2n_cert_chain_and_key_load_pem(chain_and_key, cert_chain_pem, private_key_pem));
    EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(config, chain_and_key));

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

        /* Run the client */
        mock_client(client_to_server[1], server_to_client[0]);
    }

    /* This is the parent, close the write end of the pipe */
    EXPECT_SUCCESS(close(client_to_server[1]));
    EXPECT_SUCCESS(close(server_to_client[0]));

    EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));
    EXPECT_SUCCESS(s2n_connection_set_config(conn, config));

    /* Make pipes non-blocking */
    EXPECT_NOT_EQUAL(fcntl(client_to_server[0], F_SETFL, fcntl(client_to_server[0], F_GETFL) | O_NONBLOCK), -1);
    EXPECT_NOT_EQUAL(fcntl(server_to_client[1], F_SETFL, fcntl(server_to_client[1], F_GETFL) | O_NONBLOCK), -1);

    /* Set up our I/O callbacks. Use stuffers for the "I/O context" */
    EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&in, 0));
    EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&out, 0));
    EXPECT_SUCCESS(s2n_connection_set_io_stuffers(&in, &out, conn));

    /* Negotiate the handshake. */
    do {
        ret = s2n_negotiate(conn, &blocked);
        EXPECT_TRUE(ret == 0 || (blocked && (errno == EAGAIN || errno == EWOULDBLOCK)));

        /* check to see if we need to copy more over from the pipes to the buffers
         * to continue the handshake */
        s2n_stuffer_recv_from_fd(&in, client_to_server[0], MAX_BUF_SIZE);
        s2n_stuffer_send_to_fd(&out, server_to_client[1], s2n_stuffer_data_available(&out));
    } while (blocked);

    /* Receive only 100 bytes of the record and try to call s2n_recv */
    n = 0;
    while (n < 100) {
        ret = s2n_stuffer_recv_from_fd(&in, client_to_server[0], 100 - n);

        if (ret < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            continue;
        }

        EXPECT_TRUE(ret > 0);
        n += ret;
    }

    /* s2n_recv should fail as we received only part of the record */
    EXPECT_FAILURE(s2n_recv(conn, buf, sizeof(buf), &blocked));
    EXPECT_TRUE(blocked == S2N_BLOCKED_ON_READ);

    /* Now try to release the buffers and expect failure as buffers are not empty */
    EXPECT_FAILURE(s2n_connection_release_buffers(conn));

    /* Read the rest of the buffer and expect s2n_recv to succeed */
    do {
        ret = s2n_stuffer_recv_from_fd(&in, client_to_server[0], MAX_BUF_SIZE);

        if (ret < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            continue;
        }

        ret = s2n_recv(conn, buf, sizeof(buf), &blocked);
    } while (ret < 0 && s2n_error_get_type(s2n_errno) == S2N_ERR_T_BLOCKED
                 && blocked == S2N_BLOCKED_ON_READ);

    /* Expect that we read the data client sent us */
    EXPECT_TRUE(ret == sizeof(buf_to_send));
    EXPECT_TRUE(memcmp(buf, buf_to_send, ret) == 0);

    /* Since full record was processed, we should be able to release buffers */
    EXPECT_SUCCESS(s2n_connection_release_buffers(conn));

    /* Shutdown after negotiating */
    uint8_t server_shutdown=0;
    do {
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

    s2n_cleanup();

    END_TEST();

    return 0;
}

