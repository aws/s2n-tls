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

#include "utils/s2n_random.h"
#include "utils/s2n_safety.h"

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
            return 1;
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
    s2n_config_free(client_config);

    s2n_cleanup();

    return 0;
}

int mock_client_iov(int writefd, int readfd, struct iovec *iov, uint32_t iov_size)
{
    struct s2n_connection *client_conn;
    struct s2n_config *client_config;
    s2n_blocked_status blocked;
    int result = 0;
    int total_size = 0, i;

    for (i = 0; i < iov_size; i++) {
        total_size += iov[i].iov_len;
    }
    uint8_t *buffer = malloc(total_size + iov[0].iov_len);
    int buffer_offs = 0;

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

    uint32_t remaining = total_size;
    while(remaining) {
        int r = s2n_recv(client_conn, &buffer[buffer_offs], remaining, &blocked);
        if (r < 0) {
            return 1;
        }
        remaining -= r;
        buffer_offs += r;
    }

    remaining = iov[0].iov_len;
    while(remaining) {
        int r = s2n_recv(client_conn, &buffer[buffer_offs], remaining, &blocked);
        if (r < 0) {
            return 1;
        }
        remaining -= r;
        buffer_offs += r;
    }

    int shutdown_rc= -1;
    do {
        shutdown_rc = s2n_shutdown(client_conn, &blocked);
    } while(shutdown_rc != 0);

    for (i = 0, buffer_offs = 0; i < iov_size; i++) {
        if (memcmp(iov[i].iov_base, &buffer[buffer_offs], iov[i].iov_len)) {
            return 1;
        }
        buffer_offs += iov[i].iov_len;
    }

    if (memcmp(iov[0].iov_base, &buffer[buffer_offs], iov[0].iov_len)) {
       return 1;
    }

    free(buffer);
    s2n_connection_free(client_conn);
    s2n_config_free(client_config);

    return 0;
}

int test_count = 0;
char *cert_chain_pem;
char *private_key_pem;
char *dhparams_pem;

int test_send(int use_iov)
{
    struct s2n_connection *conn;
    struct s2n_config *config;
    s2n_blocked_status blocked;
    int status;
    pid_t pid;
    int server_to_client[2];
    int client_to_server[2];
    struct s2n_cert_chain_and_key *chain_and_key;

    EXPECT_NOT_NULL(config = s2n_config_new());
    EXPECT_SUCCESS(s2n_read_test_pem(S2N_DEFAULT_TEST_CERT_CHAIN, cert_chain_pem, S2N_MAX_TEST_PEM_SIZE));
    EXPECT_SUCCESS(s2n_read_test_pem(S2N_DEFAULT_TEST_PRIVATE_KEY, private_key_pem, S2N_MAX_TEST_PEM_SIZE));
    EXPECT_NOT_NULL(chain_and_key = s2n_cert_chain_and_key_new());
    EXPECT_SUCCESS(s2n_cert_chain_and_key_load_pem(chain_and_key, cert_chain_pem, private_key_pem));
    EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(config, chain_and_key));
    EXPECT_SUCCESS(s2n_read_test_pem(S2N_DEFAULT_TEST_DHPARAMS, dhparams_pem, S2N_MAX_TEST_PEM_SIZE));
    EXPECT_SUCCESS(s2n_config_add_dhparams(config, dhparams_pem));

    /* Get some random data to send/receive */
    uint32_t data_size = 0;
    DEFER_CLEANUP(struct s2n_blob blob = {0}, s2n_free);
    int iov_payload_size = 8, iov_size = 16;
    struct iovec* iov = NULL;
    if (!use_iov) {
        data_size = 10000000;
        s2n_alloc(&blob, data_size);
        EXPECT_SUCCESS(s2n_get_urandom_data(&blob));
    } else {
        iov = malloc(sizeof(*iov) * iov_size);
        data_size = 0;
        for (int i = 0; i < iov_size; i++, iov_payload_size *= 2) {
            struct s2n_blob blob_local;
            iov[i].iov_base = blob_local.data = malloc(iov_payload_size);
            iov[i].iov_len = blob_local.size = iov_payload_size;
            EXPECT_SUCCESS(s2n_get_urandom_data(&blob));
            data_size += iov_payload_size;
        }
    }

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
        const int client_rc = !use_iov ? mock_client(client_to_server[1], server_to_client[0], blob.data, data_size)
            : mock_client_iov(client_to_server[1], server_to_client[0], iov, iov_size);

        _exit(client_rc);
    }

    /* This is the parent */
    EXPECT_SUCCESS(close(client_to_server[1]));
    EXPECT_SUCCESS(close(server_to_client[0]));

    EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));
    EXPECT_SUCCESS(s2n_connection_set_config(conn, config));

    /* Use small records in order to have more chance fitting full record into pipe */
    EXPECT_SUCCESS(s2n_connection_prefer_low_latency(conn));

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
    uint8_t *ptr = blob.data;
    uint32_t iov_offs = 0;
    while (remaining) {
        int r = !use_iov ? s2n_send(conn, ptr, remaining, &blocked) :
            s2n_sendv_with_offset(conn, iov, iov_size, iov_offs, &blocked);
        if (r < 0 && blocked == S2N_BLOCKED_ON_WRITE) {
            /* We reached a blocked state and made no forward progress last call */
            break;
        }
        EXPECT_TRUE(r > 0);
        remaining -= r;
        if (!use_iov) {
            ptr += r;
        } else {
            iov_offs += r;
        }
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
        int r = !use_iov ? s2n_send(conn, ptr, remaining, &blocked) :
            s2n_sendv_with_offset(conn, iov, iov_size, iov_offs, &blocked);
        EXPECT_TRUE(r > 0);
        remaining -= r;
        if (!use_iov) {
            ptr += r;
        } else {
            iov_offs += r;
        }
    }

    if (use_iov) {
        int r = s2n_sendv(conn, iov, 1, &blocked);
        EXPECT_TRUE(r > 0);
    }

    EXPECT_SUCCESS(s2n_shutdown(conn, &blocked));
    EXPECT_SUCCESS(s2n_connection_free(conn));

    /* Clean up */
    EXPECT_EQUAL(waitpid(-1, &status, 0), pid);
    EXPECT_EQUAL(status, 0);
    EXPECT_SUCCESS(s2n_config_free(config));
    EXPECT_SUCCESS(s2n_cert_chain_and_key_free(chain_and_key));

    if (iov) {
        for (int i = 0; i < iov_size; i++) {
            free(iov[i].iov_base);
        }
        free(iov);
    }

    return 0;
}

int main(int argc, char **argv)
{
    /* Ignore SIGPIPE */
    signal(SIGPIPE, SIG_IGN);

#define test_count _test_count
    BEGIN_TEST();
#undef test_count
    EXPECT_NOT_NULL(cert_chain_pem = malloc(S2N_MAX_TEST_PEM_SIZE));
    EXPECT_NOT_NULL(private_key_pem = malloc(S2N_MAX_TEST_PEM_SIZE));
    EXPECT_NOT_NULL(dhparams_pem = malloc(S2N_MAX_TEST_PEM_SIZE));
    test_send(0);
    test_send(1);
    free(cert_chain_pem);
    free(private_key_pem);
    free(dhparams_pem);
    END_TEST();
    return 0;
}
