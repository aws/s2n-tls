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

#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

#include "s2n_test.h"
#include "testlib/s2n_testlib.h"

/* There are issues with MacOS and FreeBSD  so we define the constant ourselves.
 * https://stackoverflow.com/a/34042435 */
#define S2N_TEST_INADDR_LOOPBACK 0x7f000001 /* 127.0.0.1 */

const char CHAR_A = 'a';
const char CHAR_B = 'b';

static S2N_RESULT start_client(int fd, int read_pipe)
{
    /* Setup connections */
    DEFER_CLEANUP(struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT),
            s2n_connection_ptr_free);
    DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(), s2n_config_ptr_free);

    DEFER_CLEANUP(struct s2n_cert_chain_and_key * chain_and_key, s2n_cert_chain_and_key_ptr_free);
    RESULT_GUARD_POSIX(s2n_test_cert_chain_and_key_new(&chain_and_key,
            S2N_DEFAULT_TEST_CERT_CHAIN, S2N_DEFAULT_TEST_PRIVATE_KEY));

    /* Setup config */
    RESULT_GUARD_POSIX(s2n_connection_set_blinding(client_conn, S2N_SELF_SERVICE_BLINDING));
    RESULT_GUARD_POSIX(s2n_connection_set_fd(client_conn, fd));
    RESULT_GUARD_POSIX(s2n_config_set_cipher_preferences(config, "default"));
    RESULT_GUARD_POSIX(s2n_config_set_unsafe_for_testing(config));
    RESULT_GUARD_POSIX(s2n_config_add_cert_chain_and_key_to_store(config, chain_and_key));
    RESULT_GUARD_POSIX(s2n_connection_set_config(client_conn, config));

    /* Do handshake */
    s2n_blocked_status blocked = S2N_NOT_BLOCKED;
    RESULT_GUARD_POSIX(s2n_negotiate(client_conn, &blocked));
    RESULT_ENSURE_EQ(client_conn->actual_protocol_version, S2N_TLS12);

    char sync = 0;
    char recv_buffer[1] = { 0 };

    {
        RESULT_GUARD_POSIX(read(read_pipe, &sync, 1));
        RESULT_GUARD_POSIX(s2n_recv(client_conn, recv_buffer, 1, &blocked));
        RESULT_ENSURE_EQ(memcmp(&CHAR_A, &recv_buffer[0], 1), 0);

        RESULT_GUARD_POSIX(read(read_pipe, &sync, 1));
        RESULT_GUARD_POSIX(s2n_recv(client_conn, recv_buffer, 1, &blocked));
        RESULT_ENSURE_EQ(memcmp(&CHAR_B, &recv_buffer[0], 1), 0);
    }

    return S2N_RESULT_OK;
}

static S2N_RESULT start_server(int fd, int write_pipe)
{
    /* Setup connections */
    DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER),
            s2n_connection_ptr_free);
    DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(), s2n_config_ptr_free);

    DEFER_CLEANUP(struct s2n_cert_chain_and_key * chain_and_key, s2n_cert_chain_and_key_ptr_free);
    EXPECT_SUCCESS(s2n_test_cert_chain_and_key_new(&chain_and_key,
            S2N_DEFAULT_TEST_CERT_CHAIN, S2N_DEFAULT_TEST_PRIVATE_KEY));

    /* Setup config */
    EXPECT_SUCCESS(s2n_connection_set_blinding(server_conn, S2N_SELF_SERVICE_BLINDING));
    EXPECT_EQUAL(s2n_connection_get_delay(server_conn), 0);
    EXPECT_SUCCESS(s2n_connection_set_fd(server_conn, fd));
    EXPECT_SUCCESS(s2n_config_set_cipher_preferences(config, "default"));
    EXPECT_SUCCESS(s2n_config_set_unsafe_for_testing(config));
    EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(config, chain_and_key));
    EXPECT_SUCCESS(s2n_connection_set_config(server_conn, config));

    /* Do handshake */
    s2n_blocked_status blocked = S2N_NOT_BLOCKED;
    EXPECT_SUCCESS(s2n_negotiate(server_conn, &blocked));
    EXPECT_EQUAL(server_conn->actual_protocol_version, S2N_TLS12);

    char sync = 0;
    char send_buffer[1] = { 0 };
    {
        send_buffer[0] = CHAR_A;
        EXPECT_SUCCESS(s2n_send(server_conn, send_buffer, 1, &blocked));
        EXPECT_SUCCESS(write(write_pipe, &sync, 1));

        send_buffer[0] = CHAR_B;
        EXPECT_SUCCESS(s2n_send(server_conn, send_buffer, 1, &blocked));
        EXPECT_SUCCESS(write(write_pipe, &sync, 1));
    }

    return S2N_RESULT_OK;
}

int main(int argc, char **argv)
{
    BEGIN_TEST();

    signal(SIGPIPE, SIG_IGN);

    /* configure real socket */
    int listener = socket(AF_INET, SOCK_STREAM, 0);
    EXPECT_SUCCESS(listener);
    struct sockaddr_in saddr = { 0 };
    saddr.sin_family = AF_INET;
    saddr.sin_addr.s_addr = htonl(S2N_TEST_INADDR_LOOPBACK);
    saddr.sin_port = 0;

    /* listen on socket address */
    socklen_t addrlen = sizeof(saddr);
    EXPECT_SUCCESS(bind(listener, (struct sockaddr *) &saddr, addrlen));
    EXPECT_SUCCESS(getsockname(listener, (struct sockaddr *) &saddr, &addrlen));

    /* used for synchronizing read and writes between client and server */
    int sync_pipe[2] = { 0 };
    EXPECT_SUCCESS(pipe(sync_pipe));

    pid_t child = fork();
    EXPECT_FALSE(child < 0);
    int status = 0, fd = 0;
    if (child) {
        /* server */
        EXPECT_SUCCESS(listen(listener, 1));
        fd = accept(listener, NULL, NULL);
        EXPECT_SUCCESS(fd);

        EXPECT_SUCCESS(close(sync_pipe[0]));
        EXPECT_OK(start_server(fd, sync_pipe[1]));

        EXPECT_EQUAL(waitpid(-1, &status, 0), child);
        EXPECT_EQUAL(status, 0);
    } else {
        /* client */
        fd = socket(AF_INET, SOCK_STREAM, 0);
        EXPECT_SUCCESS(fd);

        /* wait for server to start up */
        EXPECT_SUCCESS(sleep(1));
        EXPECT_SUCCESS(connect(fd, (struct sockaddr *) &saddr, addrlen));

        EXPECT_SUCCESS(close(sync_pipe[1]));
        EXPECT_OK(start_client(fd, sync_pipe[0]));
        exit(0);
    }

    END_TEST();
}
