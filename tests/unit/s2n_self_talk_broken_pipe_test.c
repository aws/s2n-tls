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

#include <stdint.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "api/s2n.h"
#include "s2n_test.h"
#include "testlib/s2n_testlib.h"
#include "tls/s2n_connection.h"
#include "tls/s2n_handshake.h"

#define SUPPORTED_CERTIFICATE_FORMATS (2)

static const char *certificate_paths[SUPPORTED_CERTIFICATE_FORMATS] = { S2N_RSA_2048_PKCS1_CERT_CHAIN, S2N_RSA_2048_PKCS8_CERT_CHAIN };
static const char *private_key_paths[SUPPORTED_CERTIFICATE_FORMATS] = { S2N_RSA_2048_PKCS1_KEY, S2N_RSA_2048_PKCS8_KEY };

/* Coordinate the broken-pipe sequence between the forked client and the parent
 * server using explicit signals instead of sleep()-based timing. This makes the
 * test both deterministic and fast.
 *
 * - to_server_fd:   client writes a byte here once it has half-closed its read
 *                   end, so the server knows it can write into the broken pipe.
 * - from_server_fd: client reads a byte here once the server has finished its
 *                   broken-pipe write test, so the client won't tear down the
 *                   socket too early.
 */
void mock_client(struct s2n_test_io_pair *io_pair, int from_client_fd, int from_server_fd)
{
    struct s2n_connection *conn = NULL;
    struct s2n_config *config = NULL;
    s2n_blocked_status blocked;
    char sync_byte = 0;

    conn = s2n_connection_new(S2N_CLIENT);
    config = s2n_config_new();
    s2n_config_disable_x509_verification(config);
    EXPECT_OK(s2n_config_set_tls12_security_policy(config));
    s2n_connection_set_config(conn, config);

    s2n_connection_set_io_pair(conn, io_pair);

    int result = s2n_negotiate(conn, &blocked);
    if (result < 0) {
        exit(1);
    }

    result = s2n_connection_free_handshake(conn);
    if (result < 0) {
        exit(1);
    }

#if defined(__FreeBSD__) || defined(__APPLE__) || defined(__OpenBSD__)
    /* On FreeBSD shutdown from one end of the socket pair does not give EPIPE. Must use close. */
    s2n_io_pair_close_one_end(io_pair, S2N_CLIENT);
#else
    /* Close client read fd to mock half closed pipe at server side */
    s2n_io_pair_shutdown_one_end(io_pair, S2N_CLIENT, SHUT_RD);
#endif

    /* signal: client's read closed, server should attempt write now */
    if (write(from_client_fd, &sync_byte, 1) != 1) {
        exit(1);
    }

    /* wait: server must finished writing */
    if (read(from_server_fd, &sync_byte, 1) != 1) {
        exit(1);
    }

    s2n_shutdown(conn, &blocked);

    result = s2n_connection_free(conn);
    if (result < 0) {
        exit(1);
    }

    result = s2n_config_free(config);
    if (result < 0) {
        exit(1);
    }

    s2n_io_pair_shutdown_one_end(io_pair, S2N_CLIENT, SHUT_WR);
    s2n_io_pair_close_one_end(io_pair, S2N_CLIENT);

    exit(0);
}

/* when `s2n_shutdown` is called on a connection with previously broken pipe, no
 * additional write is attempted. 
 */
int main(int argc, char **argv)
{
    struct s2n_connection *conn = NULL;
    struct s2n_config *config = NULL;
    s2n_blocked_status blocked;
    int status = 0;
    char cert_chain_pem[S2N_MAX_TEST_PEM_SIZE];
    char private_key_pem[S2N_MAX_TEST_PEM_SIZE];

    BEGIN_TEST();

    {
        struct s2n_cert_chain_and_key *chain_and_keys[SUPPORTED_CERTIFICATE_FORMATS];

        /* Create a pipe */
        DEFER_CLEANUP(struct s2n_test_io_pair io_pair = { 0 }, s2n_io_pair_close);
        EXPECT_SUCCESS(s2n_io_pair_init(&io_pair));

        /* Synchronization pipes between the server (parent) and client (child).
         * signal_from_client: client -> server, signal_from_server: server -> client. */
        int signal_from_client[2] = { 0 };
        int signal_from_server[2] = { 0 };
        EXPECT_EQUAL(pipe(signal_from_client), 0);
        EXPECT_EQUAL(pipe(signal_from_server), 0);

        /* Create a child process */
        pid_t pid = fork();
        if (pid == 0) {
            /* This is the client process, close the server end of the pipe */
            EXPECT_SUCCESS(s2n_io_pair_close_one_end(&io_pair, S2N_SERVER));

            /* Close the unused ends of the sync pipes */
            EXPECT_EQUAL(close(signal_from_client[0]), 0);
            EXPECT_EQUAL(close(signal_from_server[1]), 0);

            /* Write the fragmented hello message */
            mock_client(&io_pair, signal_from_client[1], signal_from_server[0]);
        }

        /* This is the server process, close the client end of the pipe */
        EXPECT_SUCCESS(s2n_io_pair_close_one_end(&io_pair, S2N_CLIENT));

        /* Close the unused ends of the sync pipes */
        EXPECT_EQUAL(close(signal_from_client[1]), 0);
        EXPECT_EQUAL(close(signal_from_server[0]), 0);

        EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));

        EXPECT_NOT_NULL(config = s2n_config_new());
        EXPECT_SUCCESS(s2n_config_set_cipher_preferences(config, "20240501"));
        for (int cert = 0; cert < SUPPORTED_CERTIFICATE_FORMATS; cert++) {
            EXPECT_SUCCESS(s2n_read_test_pem(certificate_paths[cert], cert_chain_pem, S2N_MAX_TEST_PEM_SIZE));
            EXPECT_SUCCESS(s2n_read_test_pem(private_key_paths[cert], private_key_pem, S2N_MAX_TEST_PEM_SIZE));
            EXPECT_NOT_NULL(chain_and_keys[cert] = s2n_cert_chain_and_key_new());
            EXPECT_SUCCESS(s2n_cert_chain_and_key_load_pem(chain_and_keys[cert], cert_chain_pem, private_key_pem));
            EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(config, chain_and_keys[cert]));
        }

        EXPECT_SUCCESS(s2n_connection_set_config(conn, config));

        /* Set up the connection to read from the fd */
        EXPECT_SUCCESS(s2n_connection_set_io_pair(conn, &io_pair));

        /* Negotiate the handshake. */
        EXPECT_SUCCESS(s2n_negotiate(conn, &blocked));
        EXPECT_EQUAL(conn->actual_protocol_version, S2N_TLS12);

        /* wait: client should close its read pipe */
        char sync_byte = 0;
        EXPECT_EQUAL(read(signal_from_client[0], &sync_byte, 1), 1);
        char buffer[1];
        /* Fist flush on half closed pipe should get EPIPE */
        ssize_t w = s2n_send(conn, buffer, 1, &blocked);
        EXPECT_EQUAL(w, -1);
        EXPECT_EQUAL(s2n_errno, S2N_ERR_IO);
        EXPECT_EQUAL(errno, EPIPE);

        /* Second flush on half closed pipe should not get EPIPE as we write is skipped */
        w = s2n_shutdown(conn, &blocked);
        EXPECT_EQUAL(w, -1);
        EXPECT_EQUAL(s2n_errno, S2N_ERR_IO);
        EXPECT_EQUAL(errno, 0);

        /* signal: server write finished, client can teardown */
        EXPECT_EQUAL(write(signal_from_server[1], &sync_byte, 1), 1);

        EXPECT_SUCCESS(s2n_connection_free(conn));
        for (int cert = 0; cert < SUPPORTED_CERTIFICATE_FORMATS; cert++) {
            EXPECT_SUCCESS(s2n_cert_chain_and_key_free(chain_and_keys[cert]));
        }
        EXPECT_SUCCESS(s2n_config_free(config));

        /* Clean up */
        EXPECT_EQUAL(waitpid(-1, &status, 0), pid);
        if (getenv("S2N_VALGRIND") == NULL) {
            EXPECT_EQUAL(status, 0);
        }
        EXPECT_SUCCESS(s2n_io_pair_close_one_end(&io_pair, S2N_SERVER));

        EXPECT_EQUAL(close(signal_from_client[0]), 0);
        EXPECT_EQUAL(close(signal_from_server[1]), 0);
    }

    END_TEST();
}
