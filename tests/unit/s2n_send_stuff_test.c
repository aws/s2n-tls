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

#include <sys/socket.h>

#include "s2n_test.h"

#include "testlib/s2n_testlib.h"

#include <sys/wait.h>
#include <unistd.h>
#include <time.h>
#include <stdint.h>

#include "api/s2n.h"

#include "tls/s2n_connection.h"
#include "tls/s2n_handshake.h"

static const char *certificate_paths = S2N_RSA_2048_PKCS1_CERT_CHAIN;
static const char *private_key_paths = S2N_RSA_2048_PKCS1_KEY;

int buffer_size = 0xffff;

void mock_client(struct s2n_test_io_pair *io_pair)
{
    char buffer[buffer_size];
    struct s2n_connection *client_conn;
    struct s2n_config *config;
    s2n_blocked_status blocked;

    /* Give the server a chance to listen */
    sleep(1);

    client_conn = s2n_connection_new(S2N_CLIENT);
    config = s2n_config_new();
    EXPECT_SUCCESS(s2n_config_set_cipher_preferences(config, "default"));
    s2n_config_disable_x509_verification(config);
    s2n_connection_set_config(client_conn, config);

    s2n_connection_set_io_pair(client_conn, io_pair);

    s2n_negotiate(client_conn, &blocked);

    s2n_connection_free_handshake(client_conn);

    uint16_t timeout = 1;
    s2n_connection_set_dynamic_record_threshold(client_conn, 0x0fff, timeout);
    int i = 10000;
    /* for (i = 1; i < buffer_size - 100; i += 100) { */
    /*     for (int j = 0; j < i; j++) { */
    buffer[33] = 33;
    /*     } */
    /*     s2n_send(conn, buffer, i, &blocked); */
    /* } */

    /* for (int j = 0; j < i; j++) { */
    /*     buffer[j] = 33; */
    /* } */

    /* release the buffers here to validate we can continue IO after */
    s2n_connection_release_buffers(client_conn);

    /* Simulate timeout second conneciton inactivity and tolerate 50 ms error */
    struct timespec sleep_time = {.tv_sec = timeout, .tv_nsec = 50000000};
    int r;
    do {
        r = nanosleep(&sleep_time, &sleep_time);
    } while (r != 0);

    /* Active application bytes consumed is reset to 0 in before writing data. */
    /* Its value should equal to bytes written after writing */
    ssize_t bytes_written = s2n_send(client_conn, buffer, i, &blocked);
    if (bytes_written != client_conn->active_application_bytes_consumed) {
        exit(0);
    }

    int shutdown_rc = -1;
    while(shutdown_rc != 0) {
        shutdown_rc = s2n_shutdown(client_conn, &blocked);
    }

    s2n_connection_free(client_conn);
    s2n_config_free(config);

    /* Give the server a chance to a void a sigpipe */
    sleep(1);

    s2n_io_pair_close_one_end(io_pair, S2N_CLIENT);

    _exit(0);
}

int main(int argc, char **argv)
{
    BEGIN_TEST();

    struct s2n_connection *server_conn;
    EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));
    struct s2n_config *config;
    EXPECT_NOT_NULL(config = s2n_config_new());
    EXPECT_SUCCESS(s2n_config_set_cipher_preferences(config, "default"));

    char *cert_chain_pem, *private_key_pem, *dhparams_pem;

    /* EXPECT_SUCCESS(s2n_disable_tls13_in_test()); */
    EXPECT_NOT_NULL(cert_chain_pem = malloc(S2N_MAX_TEST_PEM_SIZE));
    EXPECT_NOT_NULL(private_key_pem = malloc(S2N_MAX_TEST_PEM_SIZE));
    EXPECT_NOT_NULL(dhparams_pem = malloc(S2N_MAX_TEST_PEM_SIZE));

    /* Create a pipe */
    struct s2n_test_io_pair io_pair;
    EXPECT_SUCCESS(s2n_io_pair_init(&io_pair));


    /* int sockfd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol); */

    signal(SIGPIPE, SIG_IGN);
    int socket_pair[2];
    /* POSIX_GUARD(socketpair(AF_INET, SOCK_STREAM, 0, socket_pair)); */
    POSIX_GUARD(socketpair(AF_UNIX, SOCK_STREAM, 0, socket_pair));
    io_pair.client = socket_pair[0];
    io_pair.server = socket_pair[1];

    /* Create a child process */
    pid_t pid;
    pid = fork();
    if (pid == 0) {
        /* This is the client process, close the server end of the pipe */
        EXPECT_SUCCESS(s2n_io_pair_close_one_end(&io_pair, S2N_SERVER));

        /* Write the fragmented hello message */
        mock_client(&io_pair);
    }

    /* This is the server process, close the client end of the pipe */
    EXPECT_SUCCESS(s2n_io_pair_close_one_end(&io_pair, S2N_CLIENT));

    /* add cert chain and key */
    struct s2n_cert_chain_and_key *chain_and_keys;
    EXPECT_NOT_NULL(chain_and_keys = s2n_cert_chain_and_key_new());

    EXPECT_SUCCESS(s2n_read_test_pem(certificate_paths, cert_chain_pem, S2N_MAX_TEST_PEM_SIZE));
    EXPECT_SUCCESS(s2n_read_test_pem(private_key_paths, private_key_pem, S2N_MAX_TEST_PEM_SIZE));
    EXPECT_SUCCESS(s2n_cert_chain_and_key_load_pem(chain_and_keys, cert_chain_pem, private_key_pem));
    EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(config, chain_and_keys));
    /* enable ktls */
    EXPECT_SUCCESS(s2n_config_ktls_enable(config));

    EXPECT_SUCCESS(s2n_connection_set_config(server_conn, config));

    /* Set up the connection to read from the fd */
    EXPECT_SUCCESS(s2n_connection_set_io_pair(server_conn, &io_pair));

    bool enabled = false;
    s2n_connection_is_ktls_enabled(server_conn, &enabled);
    EXPECT_FALSE(enabled);

    /* Negotiate the handshake. */
    s2n_blocked_status blocked;
    EXPECT_SUCCESS(s2n_negotiate(server_conn, &blocked));
    EXPECT_EQUAL(server_conn->actual_protocol_version, S2N_TLS12);

        char buffer[buffer_size];
        /* for (int i = 1; i < buffer_size; i += 100) { */
            char * ptr = buffer;
            int size = 10000;


            do {
                int bytes_read = 0;
                EXPECT_SUCCESS(bytes_read = s2n_recv(server_conn, ptr, size, &blocked));
                fprintf(stdout, "done reading some---------- %d \n", bytes_read);

                size -= bytes_read;
                ptr += bytes_read;
            } while(size);

        /*     for (int j = 0; j < i; j++) { */
        EXPECT_EQUAL(buffer[33], 33);
        /*     } */

        /* release the buffers here to validate we can continue IO after */
        EXPECT_SUCCESS(s2n_connection_release_buffers(server_conn));
        /* } */

        int shutdown_rc = -1;
        do {
            shutdown_rc = s2n_shutdown(server_conn, &blocked);
            EXPECT_TRUE(shutdown_rc == 0 || (errno == EAGAIN && blocked));
        } while(shutdown_rc != 0);

        EXPECT_SUCCESS(s2n_connection_free(server_conn));
        EXPECT_SUCCESS(s2n_cert_chain_and_key_free(chain_and_keys));
        EXPECT_SUCCESS(s2n_config_free(config));

        /* Clean up */
        int status;
        EXPECT_EQUAL(waitpid(-1, &status, 0), pid);
        EXPECT_EQUAL(status, 0);
        EXPECT_SUCCESS(s2n_io_pair_close_one_end(&io_pair, S2N_SERVER));
    /* } */

    /* free */
    free(cert_chain_pem);
    free(private_key_pem);
    free(dhparams_pem);

    END_TEST();
    return 0;
}
