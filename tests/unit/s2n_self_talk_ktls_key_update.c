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

#include "s2n.h"
#include "s2n_test.h"
#include "stdio.h"
#include "testlib/s2n_testlib.h"
#include <sys/socket.h>
#include <fcntl.h>

#define S2N_MODE_COUNT 2
#define S2N_SECRET_TYPE_COUNT 5

static int s2n_test_secret_handler(void* context, struct s2n_connection *conn,
                                   s2n_secret_type_t secret_type,
                                   uint8_t *secret, uint8_t secret_size)
{
    /* Verify context passed through correctly */
    struct s2n_blob (*secrets)[S2N_SECRET_TYPE_COUNT] = context;
    EXPECT_NOT_NULL(secrets);

    /* Save secret for later */
    EXPECT_SUCCESS(s2n_alloc(&secrets[conn->mode][secret_type], secret_size));
    EXPECT_MEMCPY_SUCCESS(secrets[conn->mode][secret_type].data, secret, secret_size);

    return S2N_SUCCESS;
}

int s2n_io_pair_init_ktls(struct s2n_test_io_pair *io_pair)
{
    signal(SIGPIPE, SIG_IGN);

    int socket_pair[2];

    /* POSIX_GUARD(socketpair(AF_UNIX, SOCK_STREAM, 0, socket_pair)); */
    POSIX_GUARD(socketpair(AF_INET, SOCK_STREAM, 0, socket_pair));

    io_pair->client = socket_pair[0];
    io_pair->server = socket_pair[1];

    return 0;
}

int s2n_fd_set_non_blocking_ktls(int fd) {
    return fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK);
}

int s2n_io_pair_ktls(struct s2n_test_io_pair *io_pair)
{
    POSIX_GUARD(s2n_io_pair_init_ktls(io_pair));

    POSIX_GUARD(s2n_fd_set_non_blocking_ktls(io_pair->client));
    POSIX_GUARD(s2n_fd_set_non_blocking_ktls(io_pair->server));

    return 0;
}

int main(int argc, char **argv)
{
    BEGIN_TEST();

    char send_buffer[0xffff];
    char recv_buffer[0xffff];

    const uint8_t *transport_params = NULL;
    uint16_t transport_params_len = 0;

    /* Setup connections */
    struct s2n_connection *client_conn, *server_conn;
    EXPECT_NOT_NULL(client_conn = s2n_connection_new(S2N_CLIENT));
    EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));

    /* Setup config */
    struct s2n_cert_chain_and_key *chain_and_key;
    EXPECT_SUCCESS(s2n_test_cert_chain_and_key_new(&chain_and_key,
            S2N_DEFAULT_ECDSA_TEST_CERT_CHAIN, S2N_DEFAULT_ECDSA_TEST_PRIVATE_KEY));

    struct s2n_config *ktls_config;
    EXPECT_NOT_NULL(ktls_config = s2n_config_new());
    EXPECT_SUCCESS(s2n_config_set_cipher_preferences(ktls_config, "default_tls13"));
    EXPECT_SUCCESS(s2n_config_set_unsafe_for_testing(ktls_config));
    EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(ktls_config, chain_and_key));
    EXPECT_SUCCESS(s2n_config_ktls_enable(ktls_config));
    EXPECT_SUCCESS(s2n_connection_set_config(server_conn, ktls_config));

    struct s2n_config *config;
    EXPECT_NOT_NULL(config = s2n_config_new());
    EXPECT_SUCCESS(s2n_config_set_cipher_preferences(config, "default_tls13"));
    EXPECT_SUCCESS(s2n_config_set_unsafe_for_testing(config));
    EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(config, chain_and_key));
    EXPECT_SUCCESS(s2n_connection_set_config(client_conn, config));

    /* Create nonblocking pipes */
    struct s2n_test_io_pair io_pair;
    EXPECT_SUCCESS(s2n_io_pair_ktls(&io_pair));
    EXPECT_SUCCESS(s2n_connection_set_io_pair(client_conn, &io_pair));
    EXPECT_SUCCESS(s2n_connection_set_io_pair(server_conn, &io_pair));

    /* Set secret handler */
    struct s2n_blob secrets[S2N_MODE_COUNT][S2N_SECRET_TYPE_COUNT] = { 0 };
    EXPECT_SUCCESS(s2n_connection_set_secret_callback(client_conn, s2n_test_secret_handler, secrets));
    EXPECT_SUCCESS(s2n_connection_set_secret_callback(server_conn, s2n_test_secret_handler, secrets));

    /* Do handshake */
    EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));

    /* Verify TLS1.3 */
    EXPECT_EQUAL(client_conn->actual_protocol_version, S2N_TLS13);
    EXPECT_EQUAL(server_conn->actual_protocol_version, S2N_TLS13);


    /* KTLS KeyUpdate test */
    {
        s2n_blocked_status blocked = 0;
        const char a = 'a';
        const char b = 'b';
        const char c = 'c';

        send_buffer[0] = a;
        EXPECT_SUCCESS(s2n_send(client_conn, send_buffer, 1, &blocked));
        EXPECT_SUCCESS(s2n_recv(server_conn, recv_buffer, 1, &blocked));
        printf("-------- %c %c %c\n", send_buffer[0], a, recv_buffer[0]);
        EXPECT_TRUE(memcmp(&a, &recv_buffer[0], 1) == 0);

        /* -------------------------- client sends */
        client_conn->key_update_pending = true;
        EXPECT_SUCCESS(s2n_key_update_send(client_conn, &blocked));

        send_buffer[0] = b;
        EXPECT_SUCCESS(s2n_send(client_conn, send_buffer, 1, &blocked));
        EXPECT_SUCCESS(s2n_recv(server_conn, recv_buffer, 1, &blocked));
        printf("-------- %c %c %c\n", send_buffer[0], b, recv_buffer[0]);
        EXPECT_TRUE(memcmp(&b, &recv_buffer[0], 1) == 0);

        /* -------------------------- server sends */
        server_conn->key_update_pending = true;
        EXPECT_SUCCESS(s2n_key_update_send(server_conn, &blocked));

        send_buffer[0] = c;
        EXPECT_SUCCESS(s2n_send(server_conn, send_buffer, 1, &blocked));
        EXPECT_SUCCESS(s2n_recv(client_conn, recv_buffer, 1, &blocked));
        printf("-------- %c %c %c\n", send_buffer[0], c, recv_buffer[0]);
        EXPECT_TRUE(memcmp(&c, &recv_buffer[0], 1) == 0);

    }
    /* KTLS KeyUpdate test */

    EXPECT_SUCCESS(s2n_connection_free(server_conn));
    EXPECT_SUCCESS(s2n_connection_free(client_conn));
    EXPECT_SUCCESS(s2n_io_pair_close(&io_pair));
    EXPECT_SUCCESS(s2n_cert_chain_and_key_free(chain_and_key));
    EXPECT_SUCCESS(s2n_config_free(config));

    END_TEST();
}
