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

#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <sys/wait.h>
#include <unistd.h>

#include "api/s2n.h"
#include "s2n_test.h"
#include "testlib/s2n_testlib.h"
#include "tls/s2n_connection.h"
#include "tls/s2n_handshake.h"
#include "utils/s2n_random.h"

#define MAX_BUF_SIZE 10000

static const uint8_t buf_to_send[1023] = { 27 };

int mock_client(struct s2n_test_io_pair *io_pair)
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
    s2n_connection_set_io_pair(conn, io_pair);

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

    exit(0);
}

/**
 * This test ensures that we don't allow releasing connection buffers if they contain part
 * of the unprocessed record, avoiding connection corruption.
 */
int main(int argc, char **argv)
{
    s2n_blocked_status blocked;
    int status;
    pid_t pid;
    char *cert_chain_pem;
    char *private_key_pem;
    uint8_t buf[sizeof(buf_to_send)];
    uint32_t n = 0;
    ssize_t ret = 0;

    BEGIN_TEST();
    EXPECT_SUCCESS(s2n_disable_tls13_in_test());

    /* Create a pipe */
    struct s2n_test_io_pair io_pair;
    EXPECT_SUCCESS(s2n_io_pair_init(&io_pair));

    /* Create a child process */
    pid = fork();
    if (pid == 0) {
        /* This is the client process, close the server end of the pipe */
        EXPECT_SUCCESS(s2n_io_pair_close_one_end(&io_pair, S2N_SERVER));

        /* Run the client */
        mock_client(&io_pair);
    }

    DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(),
            s2n_config_ptr_free);
    DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_SERVER),
            s2n_connection_ptr_free);
    DEFER_CLEANUP(struct s2n_cert_chain_and_key *chain_and_key = s2n_cert_chain_and_key_new(),
            s2n_cert_chain_and_key_ptr_free);
    DEFER_CLEANUP(struct s2n_stuffer in, s2n_stuffer_free);
    DEFER_CLEANUP(struct s2n_stuffer out, s2n_stuffer_free);

    EXPECT_NOT_NULL(cert_chain_pem = malloc(S2N_MAX_TEST_PEM_SIZE));
    EXPECT_NOT_NULL(private_key_pem = malloc(S2N_MAX_TEST_PEM_SIZE));
    EXPECT_SUCCESS(s2n_read_test_pem(S2N_DEFAULT_TEST_CERT_CHAIN, cert_chain_pem, S2N_MAX_TEST_PEM_SIZE));
    EXPECT_SUCCESS(s2n_read_test_pem(S2N_DEFAULT_TEST_PRIVATE_KEY, private_key_pem, S2N_MAX_TEST_PEM_SIZE));
    EXPECT_SUCCESS(s2n_cert_chain_and_key_load_pem(chain_and_key, cert_chain_pem, private_key_pem));
    EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(config, chain_and_key));

    /* This is the server process, close the client end of the pipe */
    EXPECT_SUCCESS(s2n_io_pair_close_one_end(&io_pair, S2N_CLIENT));

    EXPECT_SUCCESS(s2n_connection_set_config(conn, config));

    /* Make pipes non-blocking */
    EXPECT_SUCCESS(s2n_fd_set_non_blocking(io_pair.server));
    EXPECT_SUCCESS(s2n_fd_set_non_blocking(io_pair.server));

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
        s2n_stuffer_recv_from_fd(&in, io_pair.server, MAX_BUF_SIZE, NULL);
        s2n_stuffer_send_to_fd(&out, io_pair.server, s2n_stuffer_data_available(&out), NULL);
    } while (blocked);

    /* Receive only 100 bytes of the record and try to call s2n_recv */
    while (n < 100) {
        ret = s2n_stuffer_recv_from_fd(&in, io_pair.server, 100 - n, &n);

        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            continue;
        } else {
            POSIX_GUARD(ret);
        }
    }

    /* s2n_recv should fail as we received only part of the record */
    EXPECT_FAILURE(s2n_recv(conn, buf, sizeof(buf), &blocked));
    EXPECT_TRUE(blocked == S2N_BLOCKED_ON_READ);

    /* Now try to release the buffers and expect failure as buffers are not empty */
    EXPECT_FAILURE(s2n_connection_release_buffers(conn));

    /* Read the rest of the buffer and expect s2n_recv to succeed */
    do {
        ret = s2n_stuffer_recv_from_fd(&in, io_pair.server, MAX_BUF_SIZE, NULL);

        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            continue;
        } else {
            POSIX_GUARD(ret);
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
    uint8_t server_shutdown = 0;
    do {
        ret = s2n_shutdown(conn, &blocked);
        EXPECT_TRUE(ret == 0 || (blocked && (errno == EAGAIN || errno == EWOULDBLOCK)));
        if (ret == 0) {
            server_shutdown = 1;
        }

        s2n_stuffer_recv_from_fd(&in, io_pair.server, MAX_BUF_SIZE, NULL);
        s2n_stuffer_send_to_fd(&out, io_pair.server, s2n_stuffer_data_available(&out), NULL);
    } while (!server_shutdown);

    EXPECT_EQUAL(waitpid(-1, &status, 0), pid);
    EXPECT_EQUAL(status, 0);

    /* Clean up */
    free(cert_chain_pem);
    free(private_key_pem);

    s2n_cleanup();

    END_TEST();

    return 0;
}
