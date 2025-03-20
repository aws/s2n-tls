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
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "api/s2n.h"
#include "s2n_test.h"
#include "testlib/s2n_testlib.h"
#include "tls/s2n_connection.h"
#include "tls/s2n_handshake.h"
#include "tls/s2n_tls13.h"

#define ALLOWED_GAP                10
#define ESTIMATED_SIZE_EXCEPT_ALPN 250
/* We add a one byte length prefix when we append a alpn */
#define NUM_OF_ALPN ((UINT16_MAX - ESTIMATED_SIZE_EXCEPT_ALPN) / 2)

/* Set the alpn to one byte so that we can control the alpn extension size */
static uint8_t application_protocol[1];

void mock_client(struct s2n_test_io_pair *io_pair)
{
    DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT), s2n_connection_ptr_free);
    EXPECT_NOT_NULL(conn);

    DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(), s2n_config_ptr_free);
    EXPECT_NOT_NULL(config);

    s2n_blocked_status blocked;

    /* Give the server a chance to listen */
    sleep(1);

    EXPECT_SUCCESS(s2n_config_disable_x509_verification(config));
    EXPECT_SUCCESS(s2n_config_set_cipher_preferences(config, "default_tls13"));

    for (int i = 0; i < NUM_OF_ALPN; i++) {
        EXPECT_SUCCESS(s2n_config_append_protocol_preference(config, application_protocol, sizeof(application_protocol)));
    }

    EXPECT_SUCCESS(s2n_connection_set_config(conn, config));

    EXPECT_SUCCESS(s2n_connection_set_io_pair(conn, io_pair));
    EXPECT_SUCCESS(s2n_connection_prefer_throughput(conn));

    EXPECT_SUCCESS(s2n_negotiate(conn, &blocked));

    EXPECT_SUCCESS(s2n_connection_free_handshake(conn));

    int shutdown_rc = -1;
    while (shutdown_rc != 0) {
        shutdown_rc = s2n_shutdown(conn, &blocked);
    }

    /* Give the server a chance to avoid a sigpipe */
    sleep(1);

    EXPECT_SUCCESS(s2n_io_pair_close_one_end(io_pair, S2N_CLIENT));

    exit(0);
}

int main(int argc, char **argv)
{
    s2n_blocked_status blocked;
    int status = 0;
    pid_t pid = 0;

    BEGIN_TEST();

    /* Create a pipe */
    struct s2n_test_io_pair io_pair;
    EXPECT_SUCCESS(s2n_io_pair_init(&io_pair));

    /* Create a child process */
    pid = fork();
    if (pid == 0) {
        /* This is the client process, close the server end of the pipe */
        EXPECT_SUCCESS(s2n_io_pair_close_one_end(&io_pair, S2N_SERVER));

        mock_client(&io_pair);
    }

    /* This is the server process, close the client end of the pipe */
    EXPECT_SUCCESS(s2n_io_pair_close_one_end(&io_pair, S2N_CLIENT));

    DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_SERVER), s2n_connection_ptr_free);
    EXPECT_NOT_NULL(conn);

    struct s2n_cert_chain_and_key *chain_and_key = NULL;
    EXPECT_SUCCESS(s2n_test_cert_chain_and_key_new(&chain_and_key,
            S2N_DEFAULT_ECDSA_TEST_CERT_CHAIN, S2N_DEFAULT_ECDSA_TEST_PRIVATE_KEY));

    DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(), s2n_config_ptr_free);
    EXPECT_NOT_NULL(config);
    EXPECT_SUCCESS(s2n_config_set_cipher_preferences(config, "default_tls13"));
    EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(config, chain_and_key));
    EXPECT_SUCCESS(s2n_connection_set_config(conn, config));
    EXPECT_SUCCESS(s2n_connection_prefer_throughput(conn));

    /* Set up the connection to read from the fd */
    EXPECT_SUCCESS(s2n_connection_set_io_pair(conn, &io_pair));

    /* Negotiate the handshake. */
    EXPECT_SUCCESS(s2n_negotiate(conn, &blocked));

    EXPECT_FALSE(conn->handshake.io.tainted);

    /* Ensure the actual size of ClientHello is extremely close to 64KB */
    struct s2n_client_hello *client_hello = s2n_connection_get_client_hello(conn);
    EXPECT_NOT_NULL(client_hello);
    ssize_t gap_to_uint16_max = UINT16_MAX - s2n_client_hello_get_raw_message_length(client_hello);
    EXPECT_TRUE(gap_to_uint16_max < ALLOWED_GAP);

    EXPECT_EQUAL(conn->actual_protocol_version, s2n_get_highest_fully_supported_tls_version());

    int shutdown_rc = -1;
    do {
        shutdown_rc = s2n_shutdown(conn, &blocked);
        EXPECT_TRUE(shutdown_rc == 0 || (errno == EAGAIN && blocked));
    } while (shutdown_rc != 0);

    /* Clean up */
    EXPECT_EQUAL(waitpid(-1, &status, 0), pid);
    EXPECT_EQUAL(status, 0);
    EXPECT_SUCCESS(s2n_io_pair_close_one_end(&io_pair, S2N_SERVER));

    EXPECT_SUCCESS(s2n_cert_chain_and_key_free(chain_and_key));

    EXPECT_SUCCESS(s2n_disable_tls13_in_test());

    END_TEST();
}
