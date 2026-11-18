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

/* Signals between the forked client and the server, in place of sleep().
 * Each array is a pipe: [0] is the read end, [1] is the write end. */
struct process_synchronizer {
    int client_tx_fd[2];
    int server_tx_fd[2];
};

static const uint8_t SIGNAL_BYTE = 1;

static void process_synchronizer_init(struct process_synchronizer *sync)
{
    EXPECT_EQUAL(pipe(sync->client_tx_fd), 0);
    EXPECT_EQUAL(pipe(sync->server_tx_fd), 0);
}

static void process_synchronizer_close(struct process_synchronizer *sync)
{
    for (int i = 0; i < 2; i++) {
        close(sync->client_tx_fd[i]);
        close(sync->server_tx_fd[i]);
    }
}

static void send_client_signal(struct process_synchronizer *sync)
{
    EXPECT_EQUAL(write(sync->client_tx_fd[1], &SIGNAL_BYTE, 1), 1);
}

static void wait_client_signal(struct process_synchronizer *sync)
{
    uint8_t received = 0;
    EXPECT_EQUAL(read(sync->client_tx_fd[0], &received, 1), 1);
}

static void send_server_signal(struct process_synchronizer *sync)
{
    EXPECT_EQUAL(write(sync->server_tx_fd[1], &SIGNAL_BYTE, 1), 1);
}

static void wait_server_signal(struct process_synchronizer *sync)
{
    uint8_t received = 0;
    EXPECT_EQUAL(read(sync->server_tx_fd[0], &received, 1), 1);
}

void mock_client(struct s2n_test_io_pair *io_pair, struct process_synchronizer *sync)
{
    struct s2n_connection *conn = NULL;
    struct s2n_config *config = NULL;
    s2n_blocked_status blocked;

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

    /* client read is closed, server should attempt write now */
    send_client_signal(sync);

    /* server must finish writing */
    wait_server_signal(sync);

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
    process_synchronizer_close(sync);

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

        DEFER_CLEANUP(struct process_synchronizer sync = { 0 }, process_synchronizer_close);
        process_synchronizer_init(&sync);

        /* Create a child process */
        pid_t pid = fork();
        if (pid == 0) {
            /* This is the client process, close the server end of the pipe */
            EXPECT_SUCCESS(s2n_io_pair_close_one_end(&io_pair, S2N_SERVER));

            /* Write the fragmented hello message */
            mock_client(&io_pair, &sync);
        }

        /* This is the server process, close the client end of the pipe */
        EXPECT_SUCCESS(s2n_io_pair_close_one_end(&io_pair, S2N_CLIENT));

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
        wait_client_signal(&sync);
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
        send_server_signal(&sync);

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
    }

    END_TEST();
}
