/*
 * Copyright 2017 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

#include "tls/s2n_connection.h"
#include "tls/s2n_handshake.h"

struct client_hello_context {
    int invoked;
    struct s2n_config *config;
};

int mock_client(int writefd, int readfd, int expect_failure)
{
    struct s2n_connection *conn;
    s2n_blocked_status blocked;
    int result = 0;
    int rc = 0;

    /* Give the server a chance to listen */
    sleep(1);

    conn = s2n_connection_new(S2N_CLIENT);
    conn->server_protocol_version = S2N_TLS12;
    conn->client_protocol_version = S2N_TLS12;
    conn->actual_protocol_version = S2N_TLS12;

    s2n_connection_set_read_fd(conn, readfd);
    s2n_connection_set_write_fd(conn, writefd);

    s2n_set_server_name(conn, "example.com");

    rc = s2n_negotiate(conn, &blocked);
    if (expect_failure) {
        if (!rc) {
            result = 1;
        }

        if (s2n_connection_get_alert(conn) != 40){
            result = 2;
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

    /* Give the server a chance to a void a sigpipe */
    sleep(1);

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

int client_hello_swap_config(struct s2n_connection *conn, void *ctx)
{
    struct client_hello_context *client_hello_ctx;
    const char *server_name;

    if (ctx == NULL) {
        return -1;
    }
    client_hello_ctx = ctx;

    /* Incremet counter to ensure that callback was invoked */
    client_hello_ctx->invoked++;

    /* Validate that we have server name */
    server_name = s2n_get_server_name(conn);
    if (server_name == NULL || strcmp(server_name, "example.com") != 0) {
        return -1;
    }

    /* Swap config */
    s2n_connection_set_config(conn, client_hello_ctx->config);
    return 0;
}

int client_hello_fail_handshake(struct s2n_connection *conn, void *ctx)
{
    struct client_hello_context *client_hello_ctx;

    if (ctx == NULL) {
        return -1;
    }
    client_hello_ctx = ctx;

    /* Incremet counter to ensure that callback was invoked */
    client_hello_ctx->invoked++;

    /* Return negative value to terminate the handshake */
    return -1;
}

int main(int argc, char **argv)
{
    char buffer[0xffff];
    struct s2n_connection *conn;
    struct s2n_config *config;
    struct s2n_config *swap_config;
    s2n_blocked_status blocked;
    int status;
    pid_t pid;
    int server_to_client[2];
    int client_to_server[2];
    struct client_hello_context client_hello_ctx;
    char *cert_chain_pem;
    char *private_key_pem;
    BEGIN_TEST();

    EXPECT_SUCCESS(setenv("S2N_ENABLE_CLIENT_MODE", "1", 0));

    /* Test config swapping in client hello callback */
    EXPECT_NOT_NULL(config = s2n_config_new());
    /* Don't set up certificate and private key for the main config, so if
     * handshake succeeds we know that config was swapped */

    /* Create a new config used, which will swap the current one */
    EXPECT_NOT_NULL(swap_config = s2n_config_new());

    EXPECT_NOT_NULL(cert_chain_pem = malloc(S2N_MAX_TEST_PEM_SIZE));
    EXPECT_NOT_NULL(private_key_pem = malloc(S2N_MAX_TEST_PEM_SIZE));
    EXPECT_SUCCESS(s2n_read_test_pem(S2N_DEFAULT_TEST_CERT_CHAIN, cert_chain_pem, S2N_MAX_TEST_PEM_SIZE));
    EXPECT_SUCCESS(s2n_read_test_pem(S2N_DEFAULT_TEST_PRIVATE_KEY, private_key_pem, S2N_MAX_TEST_PEM_SIZE));
    EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key(swap_config, cert_chain_pem, private_key_pem));

    /* Prepare context */
    client_hello_ctx.invoked = 0;
    client_hello_ctx.config = swap_config;

    /* Set up the callback to swap config on client hello */
    EXPECT_SUCCESS(s2n_config_set_client_hello_cb(config, client_hello_swap_config, &client_hello_ctx));

    /* Create a pipe */
    EXPECT_SUCCESS(pipe(server_to_client));
    EXPECT_SUCCESS(pipe(client_to_server));

    /* Create a child process */
    pid = fork();
    if (pid == 0) {
        /* This is the child process, close the read end of the pipe */
        EXPECT_SUCCESS(close(client_to_server[0]));
        EXPECT_SUCCESS(close(server_to_client[1]));

        mock_client(client_to_server[1], server_to_client[0], 0);
    }

    /* This is the parent */
    EXPECT_SUCCESS(close(client_to_server[1]));
    EXPECT_SUCCESS(close(server_to_client[0]));

    EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));
    conn->server_protocol_version = S2N_TLS12;
    conn->client_protocol_version = S2N_TLS12;
    conn->actual_protocol_version = S2N_TLS12;

    EXPECT_SUCCESS(s2n_connection_set_config(conn, config));

    /* Set up the connection to read from the fd */
    EXPECT_SUCCESS(s2n_connection_set_read_fd(conn, client_to_server[0]));
    EXPECT_SUCCESS(s2n_connection_set_write_fd(conn, server_to_client[1]));

    /* Negotiate the handshake. */
    EXPECT_SUCCESS(s2n_negotiate(conn, &blocked));

    /* Ensure that callback was invoked */
    EXPECT_EQUAL(client_hello_ctx.invoked, 1);

    /* Expect NULL negotiated protocol */
    EXPECT_EQUAL(s2n_get_application_protocol(conn), NULL);

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

    /* Clean up */
    EXPECT_EQUAL(waitpid(-1, &status, 0), pid);
    EXPECT_EQUAL(status, 0);
    EXPECT_SUCCESS(s2n_config_free(config));
    EXPECT_SUCCESS(s2n_config_free(swap_config));

    /* Test rejecting connection in client hello callback */
    EXPECT_NOT_NULL(config = s2n_config_new());
    EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key(config, cert_chain_pem, private_key_pem));

    /* Setup ClientHello callback */
    client_hello_ctx.invoked = 0;
    client_hello_ctx.config = NULL;
    EXPECT_SUCCESS(s2n_config_set_client_hello_cb(config, client_hello_fail_handshake, &client_hello_ctx));

    /* Create a pipe */
    EXPECT_SUCCESS(pipe(server_to_client));
    EXPECT_SUCCESS(pipe(client_to_server));

    /* Create a child process */
    pid = fork();
    if (pid == 0) {
        /* This is the child process, close the read end of the pipe */
        EXPECT_SUCCESS(close(client_to_server[0]));
        EXPECT_SUCCESS(close(server_to_client[1]));

        mock_client(client_to_server[1], server_to_client[0], 1);
    }

    /* This is the parent */
    EXPECT_SUCCESS(close(client_to_server[1]));
    EXPECT_SUCCESS(close(server_to_client[0]));

    EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));
    conn->server_protocol_version = S2N_TLS12;
    conn->client_protocol_version = S2N_TLS12;
    conn->actual_protocol_version = S2N_TLS12;

    EXPECT_SUCCESS(s2n_connection_set_config(conn, config));

    /* s2n_negotiate will fail, which ordinarily would delay with a sleep.
     * Remove the sleep and fake the delay with a mock time routine */
    EXPECT_SUCCESS(s2n_connection_set_blinding(conn, S2N_SELF_SERVICE_BLINDING));
    EXPECT_SUCCESS(s2n_config_set_nanoseconds_since_epoch_callback(config, mock_nanoseconds_since_epoch, NULL));

    /* Set up the connection to read from the fd */
    EXPECT_SUCCESS(s2n_connection_set_read_fd(conn, client_to_server[0]));
    EXPECT_SUCCESS(s2n_connection_set_write_fd(conn, server_to_client[1]));

    /* Negotiate the handshake. */
    EXPECT_FAILURE(s2n_negotiate(conn, &blocked));

    /* Ensure that callback was invoked */
    EXPECT_EQUAL(client_hello_ctx.invoked, 1);

    /* Shutdown to flush alert. Expect failure as client doesn't send close
     * notify */
    EXPECT_FAILURE(s2n_shutdown(conn, &blocked));
    EXPECT_SUCCESS(s2n_connection_free(conn));

    /* Clean up */
    EXPECT_EQUAL(waitpid(-1, &status, 0), pid);
    EXPECT_EQUAL(status, 0);
    EXPECT_SUCCESS(s2n_config_free(config));
    free(cert_chain_pem);
    free(private_key_pem);

    END_TEST();

    return 0;
}
