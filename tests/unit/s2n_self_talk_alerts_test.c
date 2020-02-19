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

#include "s2n_test.h"

#include "testlib/s2n_testlib.h"

#include <sys/wait.h>
#include <unistd.h>
#include <stdint.h>
#include <signal.h>
#include <fcntl.h>

#include <s2n.h>

#define TLS_ALERT                     21
#define TLS_ALERT_VERSION             0x03, 0x03
#define TLS_ALERT_LENGTH              0x00, 0x02

#define TLS_ALERT_LEVEL_WARNING       1
#define TLS_ALERT_LEVEL_FATAL         2

#define TLS_ALERT_CLOSE_NOTIFY        0
#define TLS_ALERT_UNRECOGNIZED_NAME   122

struct alert_ctx {
    int write_fd;
    int invoked;

    uint8_t level;
    uint8_t code;
};

int mock_client(struct s2n_test_piped_io *piped_io, s2n_alert_behavior alert_behavior, int expect_failure)
{
    struct s2n_connection *conn;
    struct s2n_config *config;
    s2n_blocked_status blocked;
    int result = 0;
    int rc = 0;

    /* Give the server a chance to listen */
    sleep(1);

    conn = s2n_connection_new(S2N_CLIENT);
    config = s2n_config_new();
    s2n_config_disable_x509_verification(config);
    s2n_config_set_alert_behavior(config, alert_behavior);
    s2n_connection_set_config(conn, config);

    s2n_connection_set_piped_io(conn, piped_io);

    rc = s2n_negotiate(conn, &blocked);
    if (expect_failure) {
        if (!rc) {
            result = 1;
        }
    } else {
        char buffer[0xffff];
        if (rc < 0) {
            result = 1;
        }

        for (int i = 1; i < 0xffff; i += 100) {
            memset(buffer, 33, sizeof(char) * i);
            s2n_send(conn, buffer, i, &blocked);
        }

        int shutdown_rc= -1;
        do {
            shutdown_rc = s2n_shutdown(conn, &blocked);
        } while(shutdown_rc != 0);
    }

    s2n_connection_free(conn);
    s2n_config_free(config);

    s2n_piped_io_close_one_end(piped_io, S2N_CLIENT);

    s2n_cleanup();

    _exit(result);
}

int mock_nanoseconds_since_epoch(void *data, uint64_t *nanoseconds)
{
    static int called = 0;

    /* When first called return 0 seconds */
    *nanoseconds = 0;

    /* When next called return 31 seconds */
    if (called) {
        *nanoseconds += (uint64_t) 31 * 1000000000;
    }

    called = 1;

    return 0;
}

int client_hello_send_alert(struct s2n_connection *conn, void *ctx)
{
    struct alert_ctx *alert = ctx;
    uint8_t alert_msg[] = { TLS_ALERT, TLS_ALERT_VERSION, TLS_ALERT_LENGTH, alert->level, alert->code };

    if (write(alert->write_fd, alert_msg, sizeof(alert_msg)) != sizeof(alert_msg)) {
        _exit(100);
    }

    alert->invoked = 1;

    return 0;
}

int main(int argc, char **argv)
{
    char buffer[0xffff];
    struct s2n_connection *conn;
    struct s2n_config *config;
    s2n_blocked_status blocked;
    int status;
    pid_t pid;
    char *cert_chain_pem;
    char *private_key_pem;
    struct s2n_cert_chain_and_key *chain_and_key;
    BEGIN_TEST();

    /* Ignore SIGPIPE */
    signal(SIGPIPE, SIG_IGN);

    EXPECT_NOT_NULL(cert_chain_pem = malloc(S2N_MAX_TEST_PEM_SIZE));
    EXPECT_NOT_NULL(private_key_pem = malloc(S2N_MAX_TEST_PEM_SIZE));
    EXPECT_SUCCESS(s2n_read_test_pem(S2N_DEFAULT_TEST_CERT_CHAIN, cert_chain_pem, S2N_MAX_TEST_PEM_SIZE));
    EXPECT_SUCCESS(s2n_read_test_pem(S2N_DEFAULT_TEST_PRIVATE_KEY, private_key_pem, S2N_MAX_TEST_PEM_SIZE));
    EXPECT_NOT_NULL(chain_and_key = s2n_cert_chain_and_key_new());
    EXPECT_SUCCESS(s2n_cert_chain_and_key_load_pem(chain_and_key, cert_chain_pem, private_key_pem));

    /* Test that we ignore Warning Alerts in S2N_ALERT_IGNORE_WARNINGS mode */
    {
        EXPECT_NOT_NULL(config = s2n_config_new());
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(config, chain_and_key));

        /* Create a pipe */
        struct s2n_test_piped_io piped_io;
        EXPECT_SUCCESS(s2n_piped_io_init(&piped_io));

        /* Set up the callback to send an alert after receiving ClientHello */
        struct alert_ctx warning_alert = {.write_fd = piped_io.server_write, .invoked = 0, .level = TLS_ALERT_LEVEL_WARNING, .code = TLS_ALERT_UNRECOGNIZED_NAME};
        EXPECT_SUCCESS(s2n_config_set_client_hello_cb(config, client_hello_send_alert, &warning_alert));

        /* Create a child process */
        pid = fork();
        if (pid == 0) {
            /* This is the client process, close the server end of the pipe */
            EXPECT_SUCCESS(s2n_piped_io_close_one_end(&piped_io, S2N_SERVER));

            mock_client(&piped_io, S2N_ALERT_IGNORE_WARNINGS, 0);
        }

        /* This is the parent */
        /* This is the server process, close the client end of the pipe */
        EXPECT_SUCCESS(s2n_piped_io_close_one_end(&piped_io, S2N_CLIENT));

        EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));
        EXPECT_SUCCESS(s2n_connection_set_config(conn, config));

        /* Set up the connection to read from the fd */
        EXPECT_SUCCESS(s2n_connection_set_piped_io(conn, &piped_io));

        /* Negotiate the handshake. */
        EXPECT_SUCCESS(s2n_negotiate(conn, &blocked));

        /* Ensure that callback was invoked */
        EXPECT_EQUAL(warning_alert.invoked, 1);

        for (int i = 1; i < 0xffff; i += 100) {
            char * ptr = buffer;
            int size = i;

            do {
                int bytes_read = 0;
                EXPECT_SUCCESS(bytes_read = s2n_recv(conn, ptr, size, &blocked));

                size -= bytes_read;
                ptr += bytes_read;
            } while(size);

            for (int j = 0; j < i; j++) {
                EXPECT_EQUAL(buffer[j], 33);
            }
        }

        EXPECT_SUCCESS(s2n_shutdown(conn, &blocked));
        EXPECT_SUCCESS(s2n_connection_free(conn));
        EXPECT_SUCCESS(s2n_piped_io_close_one_end(&piped_io, S2N_SERVER));

        /* Clean up */
        EXPECT_EQUAL(waitpid(-1, &status, 0), pid);
        EXPECT_EQUAL(status, 0);
        EXPECT_SUCCESS(s2n_config_free(config));
    }

    /* Test that we don't ignore Fatal Alerts in S2N_ALERT_IGNORE_WARNINGS mode */
    {
        EXPECT_NOT_NULL(config = s2n_config_new());
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(config, chain_and_key));

        /* Create a pipe */
        struct s2n_test_piped_io piped_io;
        EXPECT_SUCCESS(s2n_piped_io_init(&piped_io));

        /* Set up the callback to send an alert after receiving ClientHello */
        struct alert_ctx fatal_alert = {.write_fd = piped_io.server_write, .invoked = 0, .level = TLS_ALERT_LEVEL_FATAL, .code = TLS_ALERT_UNRECOGNIZED_NAME};
        EXPECT_SUCCESS(s2n_config_set_client_hello_cb(config, client_hello_send_alert, &fatal_alert));

        /* Create a child process */
        pid = fork();
        if (pid == 0) {
            /* This is the client process, close the server end of the pipe */
            EXPECT_SUCCESS(s2n_piped_io_close_one_end(&piped_io, S2N_SERVER));

            mock_client(&piped_io, S2N_ALERT_IGNORE_WARNINGS, 1);
        }

        /* This is the server process, close the client end of the pipe */
        EXPECT_SUCCESS(s2n_piped_io_close_one_end(&piped_io, S2N_CLIENT));

        EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));
        EXPECT_SUCCESS(s2n_connection_set_config(conn, config));

        /* Set up the connection to read from the fd */
        EXPECT_SUCCESS(s2n_connection_set_piped_io(conn, &piped_io));

        /* Negotiate the handshake. */
        EXPECT_FAILURE(s2n_negotiate(conn, &blocked));

        /* Ensure that callback was invoked */
        EXPECT_EQUAL(fatal_alert.invoked, 1);

        EXPECT_SUCCESS(s2n_connection_free(conn));
        EXPECT_SUCCESS(s2n_piped_io_close_one_end(&piped_io, S2N_SERVER));

        /* Clean up */
        EXPECT_EQUAL(waitpid(-1, &status, 0), pid);
        EXPECT_EQUAL(status, 0);
        EXPECT_SUCCESS(s2n_config_free(config));
    }

    /* Test that we don't ignore Warning Alerts in S2N_ALERT_FAIL_ON_WARNINGS mode */
    {
        EXPECT_NOT_NULL(config = s2n_config_new());
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(config, chain_and_key));

        /* Create a pipe */
        struct s2n_test_piped_io piped_io;
        EXPECT_SUCCESS(s2n_piped_io_init(&piped_io));

        /* Set up the callback to send an alert after receiving ClientHello */
        struct alert_ctx warning_alert = {.write_fd = piped_io.server_write, .invoked = 0, .level = TLS_ALERT_LEVEL_WARNING, .code = TLS_ALERT_UNRECOGNIZED_NAME};
        EXPECT_SUCCESS(s2n_config_set_client_hello_cb(config, client_hello_send_alert, &warning_alert));

        /* Create a child process */
        pid = fork();
        if (pid == 0) {
            /* This is the client process, close the server end of the pipe */
            EXPECT_SUCCESS(s2n_piped_io_close_one_end(&piped_io, S2N_SERVER));

            mock_client(&piped_io, S2N_ALERT_FAIL_ON_WARNINGS, 1);
        }

        /* This is the server process, close the client end of the pipe */
        EXPECT_SUCCESS(s2n_piped_io_close_one_end(&piped_io, S2N_CLIENT));

        EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));
        EXPECT_SUCCESS(s2n_connection_set_config(conn, config));

        /* Set up the connection to read from the fd */
        EXPECT_SUCCESS(s2n_connection_set_piped_io(conn, &piped_io));

        /* Negotiate the handshake. */
        EXPECT_FAILURE(s2n_negotiate(conn, &blocked));

        /* Ensure that callback was invoked */
        EXPECT_EQUAL(warning_alert.invoked, 1);

        EXPECT_SUCCESS(s2n_connection_free(conn));
        EXPECT_SUCCESS(s2n_piped_io_close_one_end(&piped_io, S2N_SERVER));

        /* Clean up */
        EXPECT_EQUAL(waitpid(-1, &status, 0), pid);
        EXPECT_EQUAL(status, 0);
        EXPECT_SUCCESS(s2n_config_free(config));
    }

    /* Shutdown */
    EXPECT_SUCCESS(s2n_cert_chain_and_key_free(chain_and_key));
    free(cert_chain_pem);
    free(private_key_pem);

    END_TEST();

    return 0;
}
