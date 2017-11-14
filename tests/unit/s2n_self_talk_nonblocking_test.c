/*
 * Copyright 2015 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

#include "utils/s2n_random.h"

#include "tls/s2n_connection.h"
#include "tls/s2n_handshake.h"

int mock_client(int writefd, int readfd, uint8_t *expected_data, uint32_t size)
{
    uint8_t *buffer = malloc(size);
    uint8_t *ptr = buffer;
    struct s2n_connection *client_conn;
    struct s2n_config *client_config;
    s2n_blocked_status blocked;
    int result = 0;

    /* Give the server a chance to listen */
    sleep(1);

    client_conn = s2n_connection_new(S2N_CLIENT);
    client_config = s2n_config_new();
    s2n_config_disable_x509_verification(client_config);
    s2n_connection_set_config(client_conn, client_config);

    s2n_connection_set_read_fd(client_conn, readfd);
    s2n_connection_set_write_fd(client_conn, writefd);

    result = s2n_negotiate(client_conn, &blocked);
    if (result < 0) {
        return 1;
    }

    /* Receive 10MB of data */
    uint32_t remaining = size;
    while(remaining) {
        int r = s2n_recv(client_conn, ptr, remaining, &blocked);
        if (r < 0) {
            continue;
        }
        remaining -= r;
        ptr += r;
    }

    int shutdown_rc= -1;
    do {
        shutdown_rc = s2n_shutdown(client_conn, &blocked);
    } while(shutdown_rc != 0);

    for (int i = 0; i < size; i++) {
        if (buffer[i] != expected_data[i]) {
            return 1;
        }
    }

    free(buffer);
    s2n_connection_free(client_conn);

    /* Give the server a chance to a void a sigpipe */
    sleep(1);

    return 0;
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

    EXPECT_SUCCESS(setenv("S2N_ENABLE_CLIENT_MODE", "1", 0));

    EXPECT_NOT_NULL(cert_chain_pem = malloc(S2N_MAX_TEST_PEM_SIZE));
    EXPECT_NOT_NULL(private_key_pem = malloc(S2N_MAX_TEST_PEM_SIZE));
    EXPECT_NOT_NULL(dhparams_pem = malloc(S2N_MAX_TEST_PEM_SIZE));
    EXPECT_NOT_NULL(config = s2n_config_new());
    EXPECT_SUCCESS(s2n_read_test_pem(S2N_DEFAULT_TEST_CERT_CHAIN, cert_chain_pem, S2N_MAX_TEST_PEM_SIZE));
    EXPECT_SUCCESS(s2n_read_test_pem(S2N_DEFAULT_TEST_PRIVATE_KEY, private_key_pem, S2N_MAX_TEST_PEM_SIZE));
    EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key(config, cert_chain_pem, private_key_pem));
    EXPECT_SUCCESS(s2n_read_test_pem(S2N_DEFAULT_TEST_DHPARAMS, dhparams_pem, S2N_MAX_TEST_PEM_SIZE));
    EXPECT_SUCCESS(s2n_config_add_dhparams(config, dhparams_pem));

    const uint32_t data_size = 10000000;
    uint8_t *data = malloc(data_size);
    EXPECT_NOT_NULL(data);

    /* Get some random data to send/receive */
    struct s2n_blob blob;
    blob.data = data;
    blob.size = data_size;
    EXPECT_SUCCESS(s2n_get_urandom_data(&blob));
    
    /* Create a pipe */
    EXPECT_SUCCESS(pipe(server_to_client));
    EXPECT_SUCCESS(pipe(client_to_server));

    /* Create a child process */
    pid = fork();
    if (pid == 0) {
        /* This is the child process, close the read end of the pipe */
        EXPECT_SUCCESS(close(client_to_server[0]));
        EXPECT_SUCCESS(close(server_to_client[1]));

        /* Run the client */
        const int client_rc = mock_client(client_to_server[1], server_to_client[0], data, data_size);

        free(data);
        _exit(client_rc);
    }

    /* This is the parent */
    EXPECT_SUCCESS(close(client_to_server[1]));
    EXPECT_SUCCESS(close(server_to_client[0]));

    EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));
    EXPECT_SUCCESS(s2n_connection_set_config(conn, config));

    /* Set up the connection to read from the fd */
    EXPECT_SUCCESS(s2n_connection_set_read_fd(conn, client_to_server[0]));
    EXPECT_SUCCESS(s2n_connection_set_write_fd(conn, server_to_client[1]));

    EXPECT_SUCCESS(s2n_connection_use_corked_io(conn));

    /* Negotiate the handshake. */
    EXPECT_SUCCESS(s2n_negotiate(conn, &blocked));

    /* Pause the child process by sending it SIGSTP */
    EXPECT_SUCCESS(kill(pid, SIGSTOP));
    
    /* Make our pipes non-blocking */
    EXPECT_NOT_EQUAL(fcntl(client_to_server[0], F_SETFL, fcntl(client_to_server[0], F_GETFL) | O_NONBLOCK), -1);
    EXPECT_NOT_EQUAL(fcntl(server_to_client[1], F_SETFL, fcntl(server_to_client[1], F_GETFL) | O_NONBLOCK), -1);

    /* Try to all 10MB of data, should be enough to fill PIPEBUF, so
       we'll get blocked at some point */
    uint32_t remaining = data_size;
    uint8_t *ptr = data;
    while (remaining) {
        int r = s2n_send(conn, ptr, remaining, &blocked);
        if (r < 0) {
            if (blocked) {
                /* We reached a blocked state and made no forward progress last call */
                break;
            }
            continue;
        }
        EXPECT_TRUE(r > 0);
        remaining -= r;
        ptr += r;
    }

    /* Remaining should be between data_size and 0 */
    EXPECT_TRUE(remaining < data_size);
    EXPECT_TRUE(remaining > 0);

    /* Wake the child process by sending it SIGCONT */
    EXPECT_SUCCESS(kill(pid, SIGCONT));

    /* Make our sockets blocking again */
    EXPECT_NOT_EQUAL(fcntl(client_to_server[0], F_SETFL, fcntl(client_to_server[0], F_GETFL) ^ O_NONBLOCK), -1);
    EXPECT_NOT_EQUAL(fcntl(server_to_client[1], F_SETFL, fcntl(server_to_client[1], F_GETFL) ^ O_NONBLOCK), -1);
    
    /* Actually send the remaining data */
    while (remaining) {
        int r = s2n_send(conn, ptr, remaining, &blocked);
        if (r < 0) {
            continue;
        }
        EXPECT_TRUE(r > 0);
        remaining -= r;
        ptr += r;
    }

    EXPECT_SUCCESS(s2n_shutdown(conn, &blocked));
    EXPECT_SUCCESS(s2n_connection_free(conn));

    /* Clean up */
    EXPECT_EQUAL(waitpid(-1, &status, 0), pid);
    EXPECT_EQUAL(status, 0);
    EXPECT_SUCCESS(s2n_config_free(config));
    free(cert_chain_pem);
    free(private_key_pem);
    free(dhparams_pem);
    END_TEST();

    free(data);

    return 0;
}
