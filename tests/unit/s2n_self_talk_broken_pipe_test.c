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

void mock_client(struct s2n_test_io_pair *io_pair)
{
    struct s2n_connection *conn;
    struct s2n_config *config;
    s2n_blocked_status blocked;

    /* Give the server a chance to listen */
    sleep(1);

    conn = s2n_connection_new(S2N_CLIENT);
    config = s2n_config_new();
    s2n_config_disable_x509_verification(config);
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
    /* Give server a chance to send data on broken pipe */
    sleep(2);

    s2n_shutdown(conn, &blocked);

    result = s2n_connection_free(conn);
    if (result < 0) {
        exit(1);
    }

    result = s2n_config_free(config);
    if (result < 0) {
        exit(1);
    }

    /* Give the server a chance to avoid a sigpipe */
    sleep(1);

    s2n_io_pair_shutdown_one_end(io_pair, S2N_CLIENT, SHUT_WR);

    exit(0);
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
    char dhparams_pem[S2N_MAX_TEST_PEM_SIZE];

    BEGIN_TEST();

    for (int is_dh_key_exchange = 0; is_dh_key_exchange <= 1; is_dh_key_exchange++) {
        struct s2n_cert_chain_and_key *chain_and_keys[SUPPORTED_CERTIFICATE_FORMATS];

        /* Create a pipe */
        struct s2n_test_io_pair io_pair;
        EXPECT_SUCCESS(s2n_io_pair_init(&io_pair));

        /* Create a child process */
        pid = fork();
        if (pid == 0) {
            /* This is the client process, close the server end of the pipe */
            EXPECT_SUCCESS(s2n_io_pair_close_one_end(&io_pair, S2N_SERVER));

            /* Write the fragmented hello message */
            mock_client(&io_pair);
        }

        /* This is the server process, close the client end of the pipe */
        EXPECT_SUCCESS(s2n_io_pair_close_one_end(&io_pair, S2N_CLIENT));

        EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));

        EXPECT_NOT_NULL(config = s2n_config_new());
        EXPECT_SUCCESS(s2n_config_set_cipher_preferences(config, "default"));
        for (int cert = 0; cert < SUPPORTED_CERTIFICATE_FORMATS; cert++) {
            EXPECT_SUCCESS(s2n_read_test_pem(certificate_paths[cert], cert_chain_pem, S2N_MAX_TEST_PEM_SIZE));
            EXPECT_SUCCESS(s2n_read_test_pem(private_key_paths[cert], private_key_pem, S2N_MAX_TEST_PEM_SIZE));
            EXPECT_NOT_NULL(chain_and_keys[cert] = s2n_cert_chain_and_key_new());
            EXPECT_SUCCESS(s2n_cert_chain_and_key_load_pem(chain_and_keys[cert], cert_chain_pem, private_key_pem));
            EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(config, chain_and_keys[cert]));
        }

        if (is_dh_key_exchange) {
            EXPECT_SUCCESS(s2n_read_test_pem(S2N_DEFAULT_TEST_DHPARAMS, dhparams_pem, S2N_MAX_TEST_PEM_SIZE));
            EXPECT_SUCCESS(s2n_config_add_dhparams(config, dhparams_pem));
        }

        EXPECT_SUCCESS(s2n_connection_set_config(conn, config));

        /* Set up the connection to read from the fd */
        EXPECT_SUCCESS(s2n_connection_set_io_pair(conn, &io_pair));

        /* Negotiate the handshake. */
        EXPECT_SUCCESS(s2n_negotiate(conn, &blocked));
        EXPECT_EQUAL(conn->actual_protocol_version, S2N_TLS12);

        /* Give client a chance to close pipe at the receiving end */
        sleep(1);
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
    return 0;
}
